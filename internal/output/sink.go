package output

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	alertpkg "github.com/yoursec/rsbp/internal/alert"
	plog "github.com/yoursec/rsbp/internal/logging"
	"github.com/yoursec/rsbp/internal/types"
)

type Sink interface {
	Name() string
	Send(ctx context.Context, alert *alertpkg.ReverseShellAlert) error
	Flush() error
	Close() error
}

type RouterMetrics struct {
	AlertsEmittedTotal *prometheus.CounterVec
	AlertsFailedTotal  *prometheus.CounterVec
	AlertLatency       *prometheus.HistogramVec
}

type SinkMetricSnapshot struct {
	Emitted uint64
	Failed  uint64
}

type Router struct {
	sinks   []Sink
	logger  *zap.Logger
	metrics *RouterMetrics
}

type DegradedSink struct {
	primary  Sink
	fallback Sink
	failures int
	degraded bool
	buffer   []*alertpkg.ReverseShellAlert
	mu       sync.Mutex
	logger   *zap.Logger

	lastReconnect time.Time
}

type Config struct {
	Enabled       []string            `mapstructure:"enabled"`
	Elasticsearch ElasticsearchConfig `mapstructure:"elasticsearch"`
	Splunk        SplunkConfig        `mapstructure:"splunk"`
	Kafka         KafkaConfig         `mapstructure:"kafka"`
	Syslog        SyslogConfig        `mapstructure:"syslog"`
	JSONL         JSONLSinkConfig     `mapstructure:"jsonl"`
	Webhook       WebhookConfig       `mapstructure:"webhook"`
}

var routerMetricsOnce sync.Once
var sinkCounters sync.Map

var alertLatencyTotalMicros atomic.Uint64
var alertLatencySamples atomic.Uint64

func newRouterMetrics() *RouterMetrics {
	m := &RouterMetrics{
		AlertsEmittedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "rsbp",
			Name:      "alerts_emitted_total",
			Help:      "Total alerts successfully emitted by sink.",
		}, []string{"sink"}),
		AlertsFailedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "rsbp",
			Name:      "alerts_failed_total",
			Help:      "Total alert emission failures by sink.",
		}, []string{"sink"}),
		AlertLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "rsbp",
			Name:      "alert_latency_seconds",
			Help:      "Latency from event/pipeline start to sink emission.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"sink"}),
	}

	routerMetricsOnce.Do(func() {
		_ = prometheus.Register(m.AlertsEmittedTotal)
		_ = prometheus.Register(m.AlertsFailedTotal)
		_ = prometheus.Register(m.AlertLatency)
	})

	return m
}

func NewRouter(sinks []Sink, logger *zap.Logger) *Router {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Router{sinks: sinks, logger: logger, metrics: newRouterMetrics()}
}

func NewDegradedSink(primary Sink, fallback Sink, logger *zap.Logger) *DegradedSink {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DegradedSink{
		primary:  primary,
		fallback: fallback,
		buffer:   make([]*alertpkg.ReverseShellAlert, 0, 1000),
		logger:   logger,
	}
}

func (d *DegradedSink) Name() string {
	if d == nil || d.primary == nil {
		return "degraded"
	}
	return d.primary.Name()
}

func (d *DegradedSink) Send(ctx context.Context, alert *alertpkg.ReverseShellAlert) error {
	if d == nil || alert == nil {
		return nil
	}

	alertLogger := plog.PipelineLogger(d.logger, alert.ID, "output")

	d.mu.Lock()
	degraded := d.degraded
	d.mu.Unlock()

	if degraded {
		d.bufferAlert(alert)
		if d.fallback != nil {
			_ = d.fallback.Send(ctx, alert)
			_ = d.fallback.Flush()
		}
		d.tryRecover(ctx, alertLogger)
		return nil
	}

	if d.primary != nil {
		if err := d.primary.Send(ctx, alert); err != nil {
			return d.onPrimaryFailure(ctx, alert, err)
		}
		if err := d.primary.Flush(); err != nil {
			return d.onPrimaryFailure(ctx, alert, err)
		}
	}

	d.mu.Lock()
	d.failures = 0
	d.mu.Unlock()

	if d.fallback != nil {
		if err := d.fallback.Send(ctx, alert); err != nil {
			alertLogger.Warn("fallback sink write failed", zap.Error(err))
		}
		_ = d.fallback.Flush()
	}
	return nil
}

func (d *DegradedSink) onPrimaryFailure(ctx context.Context, alert *alertpkg.ReverseShellAlert, err error) error {
	alertLogger := plog.PipelineLogger(d.logger, alert.ID, "output")
	d.mu.Lock()
	d.failures++
	if d.failures >= 3 && !d.degraded {
		d.degraded = true
		alertLogger.Error("ES sink degraded, routing to JSONL fallback")
	}
	degraded := d.degraded
	d.mu.Unlock()

	if degraded {
		d.bufferAlert(alert)
		if d.fallback != nil {
			_ = d.fallback.Send(ctx, alert)
			_ = d.fallback.Flush()
		}
		return nil
	}

	return err
}

func (d *DegradedSink) tryRecover(ctx context.Context, logger *zap.Logger) {
	d.mu.Lock()
	if !d.degraded {
		d.mu.Unlock()
		return
	}
	if !d.lastReconnect.IsZero() && time.Since(d.lastReconnect) < 30*time.Second {
		d.mu.Unlock()
		return
	}
	d.lastReconnect = time.Now()
	buffer := append([]*alertpkg.ReverseShellAlert(nil), d.buffer...)
	d.mu.Unlock()

	if d.primary == nil {
		return
	}
	for _, item := range buffer {
		if err := d.primary.Send(ctx, item); err != nil {
			return
		}
	}
	if err := d.primary.Flush(); err != nil {
		return
	}

	replayCount := len(buffer)
	if replayCount > 1000 {
		replayCount = 1000
	}
	d.mu.Lock()
	d.degraded = false
	d.failures = 0
	d.buffer = d.buffer[:0]
	d.mu.Unlock()

	logger.Info("ES sink recovered, replaying N buffered alerts", zap.Int("replay_count", replayCount))
}

func (d *DegradedSink) bufferAlert(a *alertpkg.ReverseShellAlert) {
	if a == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.buffer) >= 1000 {
		d.buffer = d.buffer[1:]
	}
	clone := *a
	clone.FiredRules = append([]string(nil), a.FiredRules...)
	clone.ScoreBreakdown = append([]alertpkg.ScoreBreakdown(nil), a.ScoreBreakdown...)
	clone.SyscallChain = append([]string(nil), a.SyscallChain...)
	clone.MITRETechniques = append([]alertpkg.MITRETechnique(nil), a.MITRETechniques...)
	d.buffer = append(d.buffer, &clone)
}

func (d *DegradedSink) Flush() error {
	if d == nil {
		return nil
	}
	if d.primary != nil {
		_ = d.primary.Flush()
	}
	if d.fallback != nil {
		_ = d.fallback.Flush()
	}
	return nil
}

func (d *DegradedSink) Close() error {
	if d == nil {
		return nil
	}
	if d.primary != nil {
		_ = d.primary.Close()
	}
	if d.fallback != nil {
		_ = d.fallback.Close()
	}
	return nil
}

func (r *Router) Send(ctx context.Context, a *alertpkg.ReverseShellAlert) {
	if r == nil || a == nil {
		return
	}

	var wg sync.WaitGroup
	for _, sink := range r.sinks {
		s := sink
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			alertLogger := plog.PipelineLogger(r.logger, a.ID, "output")

			if err := s.Send(timeoutCtx, a); err != nil {
				r.metrics.AlertsFailedTotal.WithLabelValues(s.Name()).Inc()
				incSinkFailed(s.Name())
				alertLogger.Warn("sink send failed",
					zap.String("sink", s.Name()),
					zap.Error(err),
					zap.Float64("latency_ms", float64(time.Since(start).Microseconds())/1000.0),
				)
				return
			}

			r.metrics.AlertsEmittedTotal.WithLabelValues(s.Name()).Inc()
			incSinkEmitted(s.Name())

			latencyBase := a.Timestamp
			if !a.PipelineStart.IsZero() {
				latencyBase = a.PipelineStart
			}
			endToEndLatency := time.Since(latencyBase)
			if endToEndLatency < 0 {
				endToEndLatency = time.Since(start)
			}
			r.metrics.AlertLatency.WithLabelValues(s.Name()).Observe(endToEndLatency.Seconds())
			observeAlertLatency(endToEndLatency)
			alertLogger.Info("sink send completed",
				zap.String("sink", s.Name()),
				zap.Float64("latency_ms", float64(endToEndLatency.Microseconds())/1000.0),
			)
		}()
	}
	wg.Wait()
}

func (r *Router) Flush() {
	if r == nil {
		return
	}
	for _, sink := range r.sinks {
		if err := sink.Flush(); err != nil {
			r.logger.Warn("sink flush failed", zap.String("sink", sink.Name()), zap.Error(err))
		}
	}
}

func (r *Router) Close() {
	if r == nil {
		return
	}
	for _, sink := range r.sinks {
		if err := sink.Close(); err != nil {
			r.logger.Warn("sink close failed", zap.String("sink", sink.Name()), zap.Error(err))
		}
	}
}

type legacyFanout struct {
	router *Router
}

func NewSinks(cfg Config, logger *zap.Logger) (*legacyFanout, error) {
	sinks := make([]Sink, 0, 6)

	enabled := make(map[string]struct{})
	for _, v := range cfg.Enabled {
		enabled[v] = struct{}{}
	}

	jsonlEnabled := true
	if _, ok := enabled["jsonl"]; !ok {
		if _, esEnabled := enabled["elasticsearch"]; !esEnabled {
			jsonlEnabled = false
		}
	}

	var jsonlSink Sink
	if jsonlEnabled {
		createdJSONL, err := NewJSONLSink(cfg.JSONL, logger)
		if err != nil {
			return nil, err
		}
		jsonlSink = createdJSONL
	}

	if _, ok := enabled["elasticsearch"]; ok {
		es, err := NewESSink(cfg.Elasticsearch, logger)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, NewDegradedSink(es, jsonlSink, logger))
	} else if jsonlSink != nil {
		sinks = append(sinks, jsonlSink)
	}
	if _, ok := enabled["splunk"]; ok {
		splunk, err := NewSplunkSink(cfg.Splunk, logger)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, splunk)
	}
	if _, ok := enabled["kafka"]; ok {
		k, err := NewKafkaSink(cfg.Kafka, logger)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, k)
	}
	if _, ok := enabled["syslog"]; ok {
		s, err := NewSyslogSink(cfg.Syslog, logger)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, s)
	}
	if _, ok := enabled["webhook"]; ok {
		w, err := NewWebhookSink(cfg.Webhook, logger)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, w)
	}

	return &legacyFanout{router: NewRouter(sinks, logger)}, nil
}

func (l *legacyFanout) Send(ctx context.Context, a *types.ReverseShellAlert) error {
	if l == nil || l.router == nil || a == nil {
		return nil
	}
	l.router.Send(ctx, convertLegacyAlert(a))
	return nil
}

func (l *legacyFanout) Close() {
	if l == nil || l.router == nil {
		return
	}
	l.router.Flush()
	l.router.Close()
}

func convertLegacyAlert(a *types.ReverseShellAlert) *alertpkg.ReverseShellAlert {
	out := &alertpkg.ReverseShellAlert{
		ID:         a.AlertID,
		Timestamp:  a.Timestamp,
		Severity:   a.Severity,
		Score:      a.Confidence,
		Pattern:    a.RuleID,
		FiredRules: []string{a.RuleID},
		Process: alertpkg.ProcessDetails{
			PID:       a.Process.PID,
			PPID:      a.Process.PPID,
			UID:       a.Process.UID,
			GID:       a.Process.GID,
			ExePath:   a.Process.Exe,
			Cmdline:   a.Process.Cmdline,
			Comm:      a.Process.Comm,
			StartTime: a.Timestamp,
		},
		Network: alertpkg.NetworkDetails{
			RemoteIP:         a.Network.RemoteIP,
			RemotePort:       fmt.Sprintf("%d", a.Network.RemotePort),
			Protocol:         a.Network.Protocol,
			ASNOrg:           a.Network.ASN,
			Country:          a.Network.GeoIPCountry,
			City:             a.Network.GeoIPCity,
			ReputationScore:  a.Network.AbuseIPDBScore,
			ThreatCategories: nil,
		},
		SyscallChain:       append([]string(nil), a.EventChain...),
		MITRETechniques:    toMITRE(a.MITREAttack),
		ForensicBundlePath: a.Forensics.MiniPCAPRef,
		HostInfo: alertpkg.HostInfo{
			Hostname:      metadataValue(a.Metadata, "hostname", a.HostID),
			OS:            metadataValue(a.Metadata, "os", ""),
			KernelVersion: metadataValue(a.Metadata, "kernel_version", ""),
			AgentVersion:  metadataValue(a.Metadata, "agent_version", ""),
		},
		PipelineStart: a.PipelineStart,
	}
	return out
}

func metadataValue(meta map[string]string, key string, fallback string) string {
	if meta == nil {
		return fallback
	}
	if v, ok := meta[key]; ok && v != "" {
		return v
	}
	return fallback
}

func toMITRE(ids []string) []alertpkg.MITRETechnique {
	out := make([]alertpkg.MITRETechnique, 0, len(ids))
	for _, id := range ids {
		out = append(out, alertpkg.MITRETechnique{ID: id, URL: "https://attack.mitre.org/techniques/" + id + "/"})
	}
	return out
}

func observeAlertLatency(d time.Duration) {
	if d < 0 {
		return
	}
	alertLatencyTotalMicros.Add(uint64(d.Microseconds()))
	alertLatencySamples.Add(1)
}

func AverageAlertLatencyMS() float64 {
	samples := alertLatencySamples.Load()
	if samples == 0 {
		return 0
	}
	totalMicros := alertLatencyTotalMicros.Load()
	return float64(totalMicros) / float64(samples) / 1000.0
}

func TotalAlertsEmitted() uint64 {
	total := uint64(0)
	sinkCounters.Range(func(_, value any) bool {
		if m, ok := value.(*sinkCounter); ok && m != nil {
			total += m.emitted.Load()
		}
		return true
	})
	return total
}

func SnapshotSinkMetrics() map[string]SinkMetricSnapshot {
	out := map[string]SinkMetricSnapshot{}
	sinkCounters.Range(func(key, value any) bool {
		name, ok := key.(string)
		if !ok {
			return true
		}
		counter, ok := value.(*sinkCounter)
		if !ok || counter == nil {
			return true
		}
		out[name] = SinkMetricSnapshot{
			Emitted: counter.emitted.Load(),
			Failed:  counter.failed.Load(),
		}
		return true
	})
	return out
}

type sinkCounter struct {
	emitted atomic.Uint64
	failed  atomic.Uint64
}

func getSinkCounter(name string) *sinkCounter {
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}
	if existing, ok := sinkCounters.Load(name); ok {
		if c, ok := existing.(*sinkCounter); ok {
			return c
		}
	}
	c := &sinkCounter{}
	actual, _ := sinkCounters.LoadOrStore(name, c)
	if existing, ok := actual.(*sinkCounter); ok {
		return existing
	}
	return c
}

func incSinkEmitted(name string) {
	getSinkCounter(name).emitted.Add(1)
}

func incSinkFailed(name string) {
	getSinkCounter(name).failed.Add(1)
}
