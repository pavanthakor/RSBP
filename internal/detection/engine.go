package detection

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/types"
)

const (
	sysExecve  = 59
	sysSocket  = 41
	sysConnect = 42
	sysDup2    = 33
	sysFork    = 57
	sysClone   = 56
	sysPipe    = 22
	sysPipe2   = 293
)

type Config struct {
	ExecConnectWindowSeconds int     `mapstructure:"exec_connect_window_seconds"`
	MinScore                 float64 `mapstructure:"min_score"`
	EnableBaseline           bool    `mapstructure:"enable_baseline"`
	BaselineFile             string  `mapstructure:"baseline_file"`
	Whitelist                WhitelistConfig
}

type WhitelistConfig struct {
	Paths        []string
	IPs          []string
	Users        []uint32
	ProcessNames []string
}

type Engine struct {
	cfg            Config
	logger         *zap.Logger
	pathSet        map[string]struct{}
	processNameSet map[string]struct{}
	userSet        map[uint32]struct{}
	ipNets         []*net.IPNet
	ipSet          map[string]struct{}
	baseline       *BaselineModel
	rules          []Rule
	mu             sync.RWMutex

	detectionsCount atomic.Uint64
	suppressedCount atomic.Uint64
}

var (
	detectionMetricsOnce   sync.Once
	detectionsTotalCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "detections_total",
		Help:      "Total detections emitted by severity and pattern.",
	}, []string{"severity", "pattern"})
	detectionsSuppressedCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "detections_suppressed_total",
		Help:      "Total detections suppressed by reason.",
	}, []string{"reason"})
	detectionScoreHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "rsbp",
		Name:      "detection_score_histogram",
		Help:      "Distribution of detection confidence scores.",
		Buckets:   []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	})
)

type MetricsSnapshot struct {
	DetectionsTotal uint64
	SuppressedTotal uint64
}

func NewEngine(cfg Config, logger *zap.Logger) *Engine {
	if cfg.ExecConnectWindowSeconds <= 0 {
		cfg.ExecConnectWindowSeconds = 20
	}
	if cfg.MinScore < 0 {
		cfg.MinScore = 0
	}
	if cfg.MinScore > 1 {
		cfg.MinScore = 1
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	e := &Engine{
		cfg:            cfg,
		logger:         logger,
		pathSet:        make(map[string]struct{}),
		processNameSet: make(map[string]struct{}),
		userSet:        make(map[uint32]struct{}),
		ipNets:         make([]*net.IPNet, 0),
		ipSet:          make(map[string]struct{}),
		baseline:       NewBaselineModel(),
		rules:          DefaultRules(),
	}
	detectionMetricsOnce.Do(func() {
		_ = prometheus.Register(detectionsTotalCounter)
		_ = prometheus.Register(detectionsSuppressedCounter)
		_ = prometheus.Register(detectionScoreHistogram)
	})
	e.buildWhitelistCaches()
	if cfg.EnableBaseline {
		if cfg.BaselineFile == "" {
			cfg.BaselineFile = "/var/lib/rsbp/baseline.json"
		}
		loaded, err := LoadBaseline(cfg.BaselineFile)
		if err == nil && loaded != nil {
			e.baseline = loaded
		} else {
			logger.Debug("baseline load skipped", zap.Error(err))
		}
	}
	return e
}

func (e *Engine) Evaluate(state *correlation.SessionState, ev types.SyscallEvent, hostID string) []*types.ReverseShellAlert {
	if state == nil {
		return nil
	}

	baseScore := e.behaviorScore(state)
	ruleEval := EvaluateRulesWithRules(RuleInput{
		Session:    state,
		Enrichment: nil,
		EventTime:  time.Unix(0, int64(ev.TimestampNS)).UTC(),
	}, e.getRules())
	if ruleEval.Score > baseScore {
		baseScore = ruleEval.Score
	}
	e.logger.Info("DETECTION DECISION",
		zap.Uint32("pid", state.PID),
		zap.String("exe", state.ExePath),
		zap.String("cmdline", state.Cmdline),
		zap.Float64("score", baseScore),
		zap.Float64("rule_score", ruleEval.Score),
		zap.Bool("complete", state.IsComplete()),
		zap.Bool("has_socket", state.HasSocket),
		zap.Bool("has_dup", state.HasDupToStdio),
		zap.String("remote_ip", state.RemoteIP.String()),
		zap.String("pipeline_stage", "detection"),
	)

	commClean := strings.ToLower(strings.TrimSpace(processNameFromSession(state)))

	neverSuppressTools := map[string]bool{
		"bash":    true,
		"sh":      true,
		"python3": true,
		"python":  true,
		"nc":      true,
		"netcat":  true,
		"ncat":    true,
		"dash":    true,
	}

	minScore := e.cfg.MinScore
	if neverSuppressTools[commClean] && minScore > 0.50 {
		minScore = 0.50
	}
	if isNeverSuppressSession(state) || isNeverSuppressProcess(commClean) {
		minScore = 0.50
	}

	// RELAX WHITELIST: Only apply if NO suspicious behavior (i.e. not IsComplete)
	if suppressed, reason := e.isWhitelisted(state); suppressed && !state.IsComplete() {
		label := "whitelist"
		if strings.TrimSpace(reason) != "" {
			label = strings.TrimSpace(reason)
		}
		detectionsSuppressedCounter.WithLabelValues(label).Inc()
		e.suppressedCount.Add(1)
		e.logger.Info("SUPPRESSED",
			zap.String("reason", label),
			zap.Uint32("pid", state.PID),
			zap.String("exe", state.ExePath),
			zap.String("remote_ip", state.RemoteIP.String()),
			zap.String("pipeline_stage", "detection"),
		)
		return nil
	}

	if baseScore < minScore {
		detectionsSuppressedCounter.WithLabelValues("score_threshold").Inc()
		e.suppressedCount.Add(1)
		e.baseline.Observe(state, baseScore, false)
		return nil
	}

	patternName := "unknown"
	if p := correlation.BestMatchPattern(state); p != nil && strings.TrimSpace(p.Name) != "" {
		patternName = p.Name
	}
	detectionsTotalCounter.WithLabelValues(string(scoreToSeverity(baseScore)), patternName).Inc()
	detectionScoreHistogram.Observe(baseScore)
	e.detectionsCount.Add(1)

	alert := &types.ReverseShellAlert{
		AlertID:       newUUIDv4(),
		Timestamp:     time.Unix(0, int64(ev.TimestampNS)).UTC(),
		HostID:        hostID,
		SessionID:     fmt.Sprintf("pid-%d", state.PID),
		EventChain:    correlatedChain(state),
		MITREAttack:   MITREForRules(ruleEval.FiredRules),
		Severity:      scoreToSeverity(baseScore),
		Confidence:    baseScore,
		RuleID:        primaryRuleID(ruleEval.FiredRules),
		Description:   "Correlated syscall chain matched reverse shell behavior",
		CorrelationID: buildCorrelationID(fmt.Sprintf("%d:%d:%d", state.PID, state.PPID, state.StartTime.UnixNano())),
		Metadata: map[string]string{
			"detector":    "heuristic-chain-v1",
			"window_sec":  fmt.Sprintf("%d", e.cfg.ExecConnectWindowSeconds),
			"category":    fmt.Sprintf("%d", state.Category),
			"fired_rules": strings.Join(ruleEval.FiredRules, ","),
		},
		PipelineStart: state.FirstEventAt,
		Process: types.ProcessContext{
			PID:     state.PID,
			PPID:    state.PPID,
			UID:     state.UID,
			GID:     state.GID,
			Comm:    processComm(state),
			Exe:     state.ExePath,
			Cmdline: state.Cmdline,
		},
		Network: types.NetworkContext{
			RemoteIP:   state.RemoteIP.String(),
			RemotePort: state.RemotePort,
			Protocol:   "tcp",
		},
	}

	e.logger.Debug("alert generated",
		zap.String("correlation_id", alert.AlertID),
		zap.String("session_id", alert.SessionID),
		zap.Float64("confidence", alert.Confidence),
		zap.String("severity", string(alert.Severity)),
		zap.String("pipeline_stage", "detection"),
		zap.Float64("latency_ms", func() float64 {
			if state.FirstEventAt.IsZero() {
				return 0
			}
			return float64(time.Since(state.FirstEventAt).Microseconds()) / 1000.0
		}()),
	)

	e.baseline.Observe(state, baseScore, true)

	return []*types.ReverseShellAlert{alert}
}

func (e *Engine) MetricsSnapshot() MetricsSnapshot {
	if e == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		DetectionsTotal: e.detectionsCount.Load(),
		SuppressedTotal: e.suppressedCount.Load(),
	}
}

func (e *Engine) WhitelistSnapshot() map[string]any {
	if e == nil {
		return map[string]any{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]any{
		"paths":         append([]string(nil), e.cfg.Whitelist.Paths...),
		"ips":           append([]string(nil), e.cfg.Whitelist.IPs...),
		"users":         append([]uint32(nil), e.cfg.Whitelist.Users...),
		"process_names": append([]string(nil), e.cfg.Whitelist.ProcessNames...),
	}
}

func newUUIDv4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return buildAlertID("fallback", uint64(time.Now().UnixNano()), 0)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]),
	)
}

func (e *Engine) SaveBaseline() error {
	if e == nil || !e.cfg.EnableBaseline || e.baseline == nil {
		return nil
	}
	if e.cfg.BaselineFile == "" {
		return nil
	}
	return e.baseline.Save(e.cfg.BaselineFile)
}

func (e *Engine) SetMinScore(score float64) {
	if e == nil {
		return
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	e.mu.Lock()
	e.cfg.MinScore = score
	e.mu.Unlock()
}

func (e *Engine) ReloadWhitelist(cfg WhitelistConfig) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.cfg.Whitelist = cfg
	e.pathSet = make(map[string]struct{})
	e.processNameSet = make(map[string]struct{})
	e.userSet = make(map[uint32]struct{})
	e.ipNets = make([]*net.IPNet, 0)
	e.ipSet = make(map[string]struct{})
	e.buildWhitelistCaches()
	e.mu.Unlock()
}

func (e *Engine) RegisterRules(rules []Rule) {
	if e == nil {
		return
	}
	e.mu.Lock()
	if len(rules) == 0 {
		e.rules = DefaultRules()
	} else {
		e.rules = append([]Rule(nil), rules...)
	}
	e.mu.Unlock()
}

func (e *Engine) getRules() []Rule {
	if e == nil {
		return DefaultRules()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.rules) == 0 {
		return DefaultRules()
	}
	return append([]Rule(nil), e.rules...)
}

func primaryRuleID(fired []string) string {
	if len(fired) == 0 {
		return "RSBP-REV-SHELL-001"
	}
	return fired[0]
}

func (e *Engine) behaviorScore(state *correlation.SessionState) float64 {
	toolName := strings.ToLower(strings.TrimSpace(processNameFromSession(state)))
	isRSTool := isNeverSuppressProcess(toolName)
	if isRSTool && state.HasConnect {
		score := 0.55
		if state.RemoteIP != nil && (state.RemoteIP.IsPrivate() || state.RemoteIP.IsLoopback()) {
			score -= 0.20
		}
		if state.HasSocket {
			score += 0.15
		}
		if state.HasDupToStdio {
			score += 0.30
		}
		if state.HasExecve {
			score += 0.10
		}
		if strings.Contains(strings.ToLower(state.Cmdline), "/dev/tcp") {
			score += 0.10
		}
		if score > 1 {
			score = 1
		}
		return score
	}

	if !state.HasExecve {
		return 0
	}

	if isRSTool && state.HasDupToStdio {
		score := 0.60
		if state.RemoteIP != nil && (state.RemoteIP.IsPrivate() || state.RemoteIP.IsLoopback()) {
			score -= 0.20
		}
		if state.HasConnect {
			score += 0.15
		}
		if state.HasSocket {
			score += 0.10
		}
		if strings.Contains(strings.ToLower(state.Cmdline), "/dev/tcp") {
			score += 0.10
		}
		if score > 1 {
			score = 1
		}
		return score
	}

	if !state.HasConnect {
		return 0
	}
	if state.LastUpdate.Sub(state.StartTime) > time.Duration(e.cfg.ExecConnectWindowSeconds)*time.Second {
		return 0
	}

	cmdlineLower := strings.ToLower(state.Cmdline)

	score := 0.55
	if state.RemoteIP != nil && (state.RemoteIP.IsPrivate() || state.RemoteIP.IsLoopback()) {
		score -= 0.20
	}
	if state.HasSocket {
		score += 0.10
	}
	if state.HasExecve && state.HasConnect && correlation.IsShellBinary(state.ExePath) {
		score += 0.15
	}
	if state.HasDupToStdio {
		score += 0.40
	}
	if state.HasForkWithPipe {
		score += 0.10
	}
	if state.Category == 2 || state.Category == 3 {
		score += 0.05
	}

	if strings.Contains(cmdlineLower, "bash -i") || strings.Contains(cmdlineLower, "/dev/tcp") {
		score += 0.10
	}

	if p := correlation.BestMatchPattern(state); p != nil {
		score += p.Confidence * 0.05
	}

	if !state.HasForkWithPipe && !strings.Contains(cmdlineLower, "/dev/tcp") && score > 0.89 {
		score = 0.89
	}
	netcatLike := strings.Contains(strings.ToLower(filepath.Base(strings.TrimSpace(state.ExePath))), "nc") ||
		strings.Contains(strings.ToLower(filepath.Base(strings.TrimSpace(state.ExePath))), "ncat") ||
		strings.Contains(strings.ToLower(filepath.Base(strings.TrimSpace(state.ExePath))), "netcat")
	if netcatLike && !state.HasSocket && !state.HasDupToStdio && !state.HasForkWithPipe && score > 0.69 {
		score = 0.69
	}
	if !correlation.IsShellBinary(state.ExePath) && !state.HasForkWithPipe && score > 0.69 {
		score = 0.69
	}
	if (strings.Contains(toolName, "python") || strings.Contains(strings.ToLower(state.ExePath), "python") || strings.Contains(cmdlineLower, "python")) && !state.HasForkWithPipe && score > 0.69 {
		score = 0.69
	}

	// ENSURE SESSION COMPLETION TRIGGERS DETECTION
	if state.IsComplete() && score < 0.60 {
		score = 0.60
	}

	if score > 1 {
		score = 1
	}
	return score
}

func (e *Engine) buildWhitelistCaches() {
	for _, p := range defaultProcessWhitelist {
		name := strings.TrimSpace(strings.ToLower(p))
		if name != "" {
			e.processNameSet[name] = struct{}{}
		}
	}

	for _, p := range e.cfg.Whitelist.Paths {
		cleaned := strings.TrimSpace(strings.ToLower(path.Clean(p)))
		if cleaned != "" {
			e.pathSet[cleaned] = struct{}{}
		}
	}
	for _, p := range e.cfg.Whitelist.ProcessNames {
		name := strings.TrimSpace(strings.ToLower(p))
		if name != "" {
			e.processNameSet[name] = struct{}{}
		}
	}
	for _, u := range e.cfg.Whitelist.Users {
		e.userSet[u] = struct{}{}
	}
	for _, raw := range e.cfg.Whitelist.IPs {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "/") {
			_, ipNet, err := net.ParseCIDR(candidate)
			if err == nil {
				e.ipNets = append(e.ipNets, ipNet)
			}
			continue
		}
		if ip := net.ParseIP(candidate); ip != nil {
			e.ipSet[ip.String()] = struct{}{}
		}
	}
}

func (e *Engine) isWhitelisted(state *correlation.SessionState) (bool, string) {
	if state == nil {
		return false, ""
	}

	procName := processNameFromSession(state)

	neverSuppress := map[string]bool{
		"bash": true, "sh": true, "python3": true, "python": true,
		"nc": true, "netcat": true, "ncat": true, "dash": true,
	}
	if neverSuppress[strings.ToLower(strings.TrimSpace(procName))] {
		return false, ""
	}

	if isNeverSuppressSession(state) || isNeverSuppressProcess(procName) {
		return false, ""
	}

	if shouldSuppressWSL2SystemProcess(state) {
		return true, "wsl2 system process"
	}
	if shouldSuppressSafePortTelemetry(state) {
		return true, "browser/IDE telemetry"
	}
	if shouldSuppressScriptChild(state) {
		return true, "common recon tool — insufficient alone"
	}
	if shouldSuppressDockerHealthCheck(state) {
		return true, "docker healthcheck"
	}
	if isDefaultWhitelistedProcessName(procName) {
		return true, "default process whitelist"
	}
	if isDefaultWhitelistedPath(state.ExePath) {
		return true, "default path whitelist"
	}
	if isDefaultWhitelistedIP(state.RemoteIP) {
		cmdlineLower := strings.ToLower(strings.TrimSpace(state.Cmdline))
		if state.HasDupToStdio || strings.Contains(cmdlineLower, "/dev/tcp") {
			return false, ""
		}
		return true, "default private/local IP"
	}
	if isDefaultSafePort(state.RemotePort) && (isDefaultWhitelistedProcessName(procName) || isDefaultWhitelistedPath(state.ExePath)) {
		return true, "default safe port whitelist"
	}

	if shouldSuppressNode443Telemetry(state) {
		return true, "browser/IDE telemetry"
	}
	if len(e.pathSet) == 0 && len(e.processNameSet) == 0 && len(e.userSet) == 0 && len(e.ipSet) == 0 && len(e.ipNets) == 0 {
		return false, ""
	}

	if _, ok := e.userSet[state.UID]; ok {
		return true, "configured user whitelist"
	}

	fullPath := strings.TrimSpace(strings.ToLower(path.Clean(state.ExePath)))
	if fullPath != "" {
		if _, ok := e.pathSet[fullPath]; ok {
			return true, "configured path whitelist"
		}
		base := strings.ToLower(filepath.Base(fullPath))
		if _, ok := e.processNameSet[base]; ok {
			return true, "configured process whitelist"
		}
	}

	if state.RemoteIP != nil {
		ip := state.RemoteIP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if _, ok := e.ipSet[ip.String()]; ok {
			return true, "configured IP whitelist"
		}
		for _, netw := range e.ipNets {
			if netw.Contains(ip) {
				return true, "configured CIDR whitelist"
			}
		}
	}

	return false, ""
}

func buildAlertID(sessionID string, ts uint64, syscall uint32) string {
	seed := fmt.Sprintf("%s:%d:%d", sessionID, ts, syscall)
	hash := sha1.Sum([]byte(seed))
	return "rsbp-" + hex.EncodeToString(hash[:8])
}

func buildCorrelationID(seed string) string {
	hash := sha1.Sum([]byte(seed))
	return hex.EncodeToString(hash[:8])
}

func scoreToSeverity(score float64) types.AlertSeverity {
	switch {
	case score >= 0.9:
		return types.SeverityCritical
	case score >= 0.7:
		return types.SeverityHigh
	case score >= 0.5:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

func correlatedChain(state *correlation.SessionState) []string {
	if state == nil {
		return nil
	}

	out := make([]string, 0, 5)
	if state.HasExecve {
		out = append(out, "execve")
	}
	if state.HasSocket {
		out = append(out, "socket")
	}
	if state.HasConnect {
		out = append(out, "connect")
	}
	if state.HasDupToStdio {
		out = append(out, "dup2")
	}
	if state.HasForkWithPipe {
		out = append(out, "fork_pipe")
	}
	return out
}

func processComm(state *correlation.SessionState) string {
	if state == nil {
		return ""
	}
	if len(state.ProcessTree) > 0 {
		return state.ProcessTree[len(state.ProcessTree)-1].Comm
	}
	if state.ExePath != "" {
		return filepath.Base(state.ExePath)
	}
	if state.RemoteIP != nil && state.RemoteIP.Equal(net.IPv4zero) {
		return "unknown"
	}
	return "unknown"
}
