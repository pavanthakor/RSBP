package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type Watchdog struct {
	lastEventTime    time.Time
	lastAlertTime    time.Time
	zeroEventTimeout time.Duration
	logger           *zap.Logger

	noAlertTimeout time.Duration
	checkInterval  time.Duration

	restartCounter prometheus.Counter
	restartTotal   atomic.Uint64

	reprobeFn     func(context.Context) error
	whitelistDump func() map[string]any
	alertsPath    string
	logDir        string
	forensicsDir  string

	mu sync.RWMutex
}

var watchdogMetricOnce sync.Once

func New(logger *zap.Logger, reprobeFn func(context.Context) error, whitelistDump func() map[string]any, logDir, alertsPath, forensicsDir string) *Watchdog {
	if logger == nil {
		logger = zap.NewNop()
	}
	w := &Watchdog{
		lastEventTime:    time.Now().UTC(),
		lastAlertTime:    time.Now().UTC(),
		zeroEventTimeout: 60 * time.Second,
		noAlertTimeout:   10 * time.Minute,
		checkInterval:    30 * time.Second,
		logger:           logger,
		reprobeFn:        reprobeFn,
		whitelistDump:    whitelistDump,
		logDir:           defaultIfEmpty(logDir, "/var/log/rsbp"),
		alertsPath:       defaultIfEmpty(alertsPath, "/var/log/rsbp/alerts.jsonl"),
		forensicsDir:     defaultIfEmpty(forensicsDir, "/var/lib/rsbp/forensics"),
	}
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "watchdog_restarts_total",
		Help:      "Total watchdog-triggered probe re-attachment attempts.",
	})
	watchdogMetricOnce.Do(func() {
		_ = prometheus.Register(counter)
	})
	w.restartCounter = counter
	return w
}

func defaultIfEmpty(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func (w *Watchdog) NoteEvent(ts time.Time) {
	if w == nil {
		return
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	w.mu.Lock()
	w.lastEventTime = ts
	w.mu.Unlock()
}

func (w *Watchdog) NoteAlert(ts time.Time) {
	if w == nil {
		return
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	w.mu.Lock()
	w.lastAlertTime = ts
	w.mu.Unlock()
}

func (w *Watchdog) Run(ctx context.Context) {
	if w == nil {
		return
	}
	ticker := time.NewTicker(w.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.check(ctx)
		}
	}
}

func (w *Watchdog) check(ctx context.Context) {
	now := time.Now().UTC()
	w.mu.RLock()
	lastEvent := w.lastEventTime
	lastAlert := w.lastAlertTime
	w.mu.RUnlock()

	if now.Sub(lastEvent) >= w.zeroEventTimeout {
		w.logger.Error("eBPF pipeline stalled",
			zap.String("pipeline_stage", "ebpf"),
			zap.Duration("silence_for", now.Sub(lastEvent)),
		)
		if w.reprobeFn != nil {
			if err := w.reprobeFn(ctx); err != nil {
				w.logger.Error("watchdog probe re-attachment failed", zap.Error(err), zap.String("pipeline_stage", "ebpf"))
			} else {
				w.restartCounter.Inc()
				w.restartTotal.Add(1)
			}
		}
	}

	if now.Sub(lastEvent) < w.zeroEventTimeout && now.Sub(lastAlert) >= w.noAlertTimeout {
		w.logger.Warn("Detection pipeline may be suppressing all events",
			zap.String("pipeline_stage", "detection"),
			zap.Duration("event_flow_age", now.Sub(lastEvent)),
			zap.Duration("alert_silence", now.Sub(lastAlert)),
		)
		if w.whitelistDump != nil {
			if payload, err := json.Marshal(w.whitelistDump()); err == nil {
				w.logger.Warn("current whitelist snapshot", zap.String("pipeline_stage", "detection"), zap.ByteString("whitelist", payload))
			}
		}
	}

	if usage, err := diskUsagePercent(w.logDir); err == nil && usage > 90 {
		w.logger.Error("/var/log/rsbp disk usage above 90%",
			zap.String("pipeline_stage", "output"),
			zap.Int("disk_usage_percent", usage),
		)
		if err := rotateAlertsImmediately(w.alertsPath); err != nil {
			w.logger.Error("failed to rotate alerts.jsonl", zap.Error(err), zap.String("pipeline_stage", "output"))
		}
		if err := deleteOldBundles(w.forensicsDir, 7*24*time.Hour); err != nil {
			w.logger.Error("failed to purge old forensics bundles", zap.Error(err), zap.String("pipeline_stage", "forensics"))
		}
	}
}

func rotateAlertsImmediately(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("alerts path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		rotated := filepath.Join(filepath.Dir(path), fmt.Sprintf("alerts.%s.jsonl", time.Now().UTC().Format("20060102-150405")))
		if err := os.Rename(path, rotated); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

func deleteOldBundles(root string, maxAge time.Duration) error {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cutoff := time.Now().UTC().Add(-maxAge)
	for _, entry := range entries {
		full := filepath.Join(root, entry.Name())
		st, statErr := os.Stat(full)
		if statErr != nil {
			continue
		}
		if st.ModTime().Before(cutoff) {
			_ = os.RemoveAll(full)
		}
	}
	return nil
}

func diskUsagePercent(path string) (int, error) {
	cmd := exec.Command("df", "-P", path)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 5 {
		return 0, fmt.Errorf("unexpected df columns")
	}
	pctRaw := strings.TrimSuffix(fields[4], "%")
	pct, err := strconv.Atoi(pctRaw)
	if err != nil {
		return 0, err
	}
	return pct, nil
}

func (w *Watchdog) Snapshot() map[string]any {
	if w == nil {
		return map[string]any{}
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return map[string]any{
		"last_event_time":        w.lastEventTime,
		"last_alert_time":        w.lastAlertTime,
		"zero_event_timeout_sec": int(w.zeroEventTimeout.Seconds()),
		"restarts_total":         w.restartTotal.Load(),
	}
}

func CleanupBySize(root string, maxTotalMB int64) error {
	if strings.TrimSpace(root) == "" || maxTotalMB <= 0 {
		return nil
	}
	type item struct {
		path string
		time time.Time
		size int64
	}
	items := make([]item, 0, 128)
	var total int64
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		full := filepath.Join(root, entry.Name())
		size := int64(0)
		_ = filepath.Walk(full, func(_ string, info os.FileInfo, walkErr error) error {
			if walkErr == nil && info != nil && !info.IsDir() {
				size += info.Size()
			}
			return nil
		})
		st, statErr := os.Stat(full)
		if statErr != nil {
			continue
		}
		total += size
		items = append(items, item{path: full, time: st.ModTime(), size: size})
	}

	limit := maxTotalMB * 1024 * 1024
	if total <= limit {
		return nil
	}

	sort.Slice(items, func(i, j int) bool { return items[i].time.Before(items[j].time) })
	for _, it := range items {
		if total <= limit {
			break
		}
		_ = os.RemoveAll(it.path)
		total -= it.size
	}
	return nil
}
