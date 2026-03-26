package enrichment

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/types"
)

type Result struct {
	Country              string        `json:"country"`
	CountryCode          string        `json:"country_code"`
	City                 string        `json:"city"`
	ASN                  uint32        `json:"asn"`
	ASNOrg               string        `json:"asn_org"`
	IsVPN                bool          `json:"is_vpn"`
	IsTor                bool          `json:"is_tor"`
	IsHosting            bool          `json:"is_hosting"`
	ReputationScore      int           `json:"reputation_score"`
	AbuseConfidenceScore int           `json:"abuse_confidence_score"`
	ThreatCategories     []string      `json:"threat_categories"`
	DomainAgeDays        int           `json:"domain_age_days"`
	IsNewlyRegistered    bool          `json:"is_newly_registered"`
	RemoteHostname       string        `json:"remote_hostname"`
	ProcessTree          []ProcessInfo `json:"process_tree"`
	OpenFDs              []FDInfo      `json:"open_fds"`
	NetworkConnections   []NetConn     `json:"network_connections"`
	EnrichmentDuration   time.Duration `json:"enrichment_duration"`
}

type Config struct {
	GeoIPDBPath       string `mapstructure:"geoip_db_path"`
	ASNDBPath         string `mapstructure:"asn_db_path"`
	AbuseIPDBAPIKey   string `mapstructure:"abuseipdb_api_key"`
	AbuseIPDBEndpoint string `mapstructure:"abuseipdb_endpoint"`
	AbuseCachePath    string `mapstructure:"abuseipdb_cache_path"`
	AbuseIPDBEnabled  bool   `mapstructure:"abuseipdb_enabled"`
	ProcRoot          string `mapstructure:"proc_root"`
}

type Enricher struct {
	geo        *GeoIPEnricher
	reputation *ReputationEnricher
	procInfo   *ProcEnricher
	cache      *ttlcache.Cache[string, *Result]
	logger     *zap.Logger
}

var (
	enrichmentDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "rsbp",
		Subsystem: "enrichment",
		Name:      "enrichment_duration_seconds",
		Help:      "Time spent enriching one session result.",
		Buckets:   prometheus.DefBuckets,
	})
	enrichmentErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rsbp",
		Subsystem: "enrichment",
		Name:      "enrichment_errors_total",
		Help:      "Total enrichment stage errors (non-fatal).",
	})
	metricsOnce sync.Once
	resultPool  = sync.Pool{New: func() any { return &Result{} }}
)

func NewEnricher(cfg Config, logger *zap.Logger) *Enricher {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.AbuseIPDBEndpoint == "" {
		cfg.AbuseIPDBEndpoint = "https://api.abuseipdb.com/api/v2/check"
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}

	metricsOnce.Do(func() {
		_ = prometheus.Register(enrichmentDuration)
		_ = prometheus.Register(enrichmentErrors)
	})

	cache := ttlcache.New[string, *Result](ttlcache.WithTTL[string, *Result](15 * time.Minute))
	go cache.Start()

	return &Enricher{
		geo:        NewGeoIPEnricher(cfg.GeoIPDBPath, cfg.ASNDBPath, logger),
		reputation: NewReputationEnricher(cfg.AbuseCachePath, cfg.AbuseIPDBAPIKey, cfg.AbuseIPDBEndpoint, cfg.AbuseIPDBEnabled, logger),
		procInfo:   NewProcEnricher(cfg.ProcRoot, logger),
		cache:      cache,
		logger:     logger,
	}
}

func (e *Enricher) Enrich(ctx context.Context, s *correlation.SessionState) (*Result, error) {
	start := time.Now()
	if e == nil {
		return &Result{}, errors.New("enricher is nil")
	}
	if s == nil {
		return &Result{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	res := borrowResult()
	var (
		geoRes  *GeoResult
		repRes  *ReputationResult
		procRes *ProcBundle
	)

	cacheKey := ""
	if s.RemoteIP != nil {
		cacheKey = s.RemoteIP.String()
	}

	if cacheKey != "" {
		if item := e.cache.Get(cacheKey); item != nil && item.Value() != nil {
			applyResult(res, item.Value())
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	if res.Country == "" && s.RemoteIP != nil {
		g.Go(func() error {
			lookup, err := e.geo.Lookup(gctx, s.RemoteIP)
			if err != nil {
				enrichmentErrors.Inc()
				e.logger.Debug("geo enrichment failed", zap.Error(err))
				return nil
			}
			geoRes = lookup
			return nil
		})

		g.Go(func() error {
			lookup, err := e.reputation.Lookup(gctx, s.RemoteIP)
			if err != nil {
				enrichmentErrors.Inc()
				e.logger.Debug("reputation enrichment failed", zap.Error(err))
				return nil
			}
			repRes = lookup
			return nil
		})
	}

	g.Go(func() error {
		lookup, err := e.procInfo.Collect(s.PID)
		if err != nil {
			enrichmentErrors.Inc()
			e.logger.Debug("proc enrichment failed", zap.Uint32("pid", s.PID), zap.Error(err))
			return nil
		}
		procRes = lookup
		return nil
	})

	_ = g.Wait()

	if geoRes != nil {
		res.Country = geoRes.Country
		res.CountryCode = geoRes.CountryCode
		res.City = geoRes.City
		res.ASN = geoRes.ASN
		res.ASNOrg = geoRes.ASNOrg
		res.IsVPN = geoRes.IsVPN
		res.IsTor = geoRes.IsTor
		res.IsHosting = geoRes.IsHosting
	}

	if repRes != nil {
		res.ReputationScore = repRes.ReputationScore
		res.AbuseConfidenceScore = repRes.AbuseConfidenceScore
		res.ThreatCategories = append([]string(nil), repRes.ThreatCategories...)
		res.DomainAgeDays = repRes.DomainAgeDays
		res.IsNewlyRegistered = repRes.IsNewlyRegistered
	}

	if procRes != nil {
		res.ProcessTree = append([]ProcessInfo(nil), procRes.ProcessTree...)
		res.OpenFDs = append([]FDInfo(nil), procRes.OpenFDs...)
		res.NetworkConnections = append([]NetConn(nil), procRes.NetworkConnections...)
	}

	if s.RemoteIP != nil {
		hostCtx, hostCancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer hostCancel()
		res.RemoteHostname = reverseDNS(hostCtx, s.RemoteIP)
	}

	sort.Strings(res.ThreatCategories)
	res.EnrichmentDuration = time.Since(start)
	enrichmentDuration.Observe(res.EnrichmentDuration.Seconds())

	out := cloneResult(res)
	releaseResult(res)

	if cacheKey != "" {
		e.cache.Set(cacheKey, cloneResult(out), 15*time.Minute)
	}

	return out, nil
}

func (e *Enricher) EnrichAlert(ctx context.Context, alert *types.ReverseShellAlert) {
	if e == nil || alert == nil {
		return
	}

	s := &correlation.SessionState{
		PID:        alert.Process.PID,
		PPID:       alert.Process.PPID,
		UID:        alert.Process.UID,
		GID:        alert.Process.GID,
		ExePath:    alert.Process.Exe,
		Cmdline:    alert.Process.Cmdline,
		RemoteIP:   net.ParseIP(alert.Network.RemoteIP),
		RemotePort: alert.Network.RemotePort,
	}

	res, err := e.Enrich(ctx, s)
	if err != nil || res == nil {
		return
	}

	if res.Country != "" {
		alert.Network.GeoIPCountry = res.Country
	}
	if res.City != "" {
		alert.Network.GeoIPCity = res.City
	}
	if res.ASNOrg != "" {
		alert.Network.ASN = res.ASNOrg
	}
	if res.AbuseConfidenceScore > 0 {
		alert.Network.AbuseIPDBScore = res.AbuseConfidenceScore
	}
}

func borrowResult() *Result {
	r := resultPool.Get().(*Result)
	resetResult(r)
	return r
}

func releaseResult(r *Result) {
	if r == nil {
		return
	}
	resetResult(r)
	resultPool.Put(r)
}

func resetResult(r *Result) {
	*r = Result{}
}

func cloneResult(in *Result) *Result {
	if in == nil {
		return &Result{}
	}
	out := *in
	out.ThreatCategories = append([]string(nil), in.ThreatCategories...)
	out.ProcessTree = append([]ProcessInfo(nil), in.ProcessTree...)
	out.OpenFDs = append([]FDInfo(nil), in.OpenFDs...)
	out.NetworkConnections = append([]NetConn(nil), in.NetworkConnections...)
	return &out
}

func applyResult(dst *Result, src *Result) {
	if dst == nil || src == nil {
		return
	}
	*dst = *cloneResult(src)
}

func reverseDNS(ctx context.Context, ip net.IP) string {
	if ip == nil {
		return ""
	}
	type out struct {
		h string
	}
	ch := make(chan out, 1)
	go func() {
		names, err := net.LookupAddr(ip.String())
		if err != nil || len(names) == 0 {
			ch <- out{}
			return
		}
		ch <- out{h: strings.TrimSuffix(names[0], ".")}
	}()

	select {
	case <-ctx.Done():
		return ""
	case v := <-ch:
		return v.h
	}
}
