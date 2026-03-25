package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const currentConfigVersion = 2

var (
	apiKeyPattern = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
)

type configValidationMode string

const (
	configValidationModeDev  configValidationMode = "dev"
	configValidationModeProd configValidationMode = "prod"
)

type whitelistPathValidationResult struct {
	ValidPaths         []string
	RemovedPaths       []string
	MissingPaths       []string
	SkippedPatternPath []string
}

func loadConfigWithLogger(configPath string, logger *zap.Logger) (*appConfig, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	rawBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(rawBytes, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("config is empty: %s", configPath)
	}

	normalized, migrationWarnings, err := normalizeAndMigrate(raw)
	if err != nil {
		return nil, err
	}
	for _, w := range migrationWarnings {
		logger.Warn("config normalization/migration", zap.String("detail", w))
	}

	cfg := &appConfig{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		Result:           cfg,
		ErrorUnused:      true,
		WeaklyTypedInput: true,
	})
	if err != nil {
		return nil, fmt.Errorf("init config decoder: %w", err)
	}
	if err := decoder.Decode(normalized); err != nil {
		return nil, fmt.Errorf("invalid config schema: %w", err)
	}

	appliedDefaults := injectDefaults(cfg, normalized)
	for _, d := range appliedDefaults {
		logger.Info("config default applied", zap.String("field", d.Field), zap.Any("value", d.Value))
	}

	mode := resolveConfigValidationMode()
	cfg.Runtime.ConfigValidationMode = string(mode)
	logger.Info("config validation mode", zap.String("mode", cfg.Runtime.ConfigValidationMode))

	pathValidation := validateAndPruneWhitelistPaths(cfg.RSBP.Whitelist.Paths, mode, logger)
	cfg.RSBP.Whitelist.Paths = pathValidation.ValidPaths
	cfg.Runtime.RemovedWhitelistPaths = append([]string(nil), pathValidation.RemovedPaths...)
	cfg.Runtime.ValidWhitelistPaths = append([]string(nil), pathValidation.ValidPaths...)
	cfg.Runtime.SkippedWhitelistPaths = append([]string(nil), pathValidation.RemovedPaths...)

	if mode == configValidationModeProd && len(pathValidation.MissingPaths) > 0 {
		return nil, newWhitelistMissingPathsError(pathValidation.MissingPaths)
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func normalizeAndMigrate(in map[string]any) (map[string]any, []string, error) {
	cfg := deepCopyMap(in)
	warnings := make([]string, 0, 8)

	ver, hasVersion := parseInt(cfg["config_version"])
	if !hasVersion {
		ver = 1
		cfg["config_version"] = strconv.Itoa(ver)
		warnings = append(warnings, "missing config_version; assuming legacy version 1")
	} else {
		cfg["config_version"] = strconv.Itoa(ver)
	}

	rsbpRaw, hasRSBP := cfg["rsbp"]
	var rsbp map[string]any
	if hasRSBP {
		m, ok := asMap(rsbpRaw)
		if !ok {
			return nil, nil, fmt.Errorf("invalid config: 'rsbp' must be a map")
		}
		rsbp = m
	} else {
		rsbp = map[string]any{}
		legacyKeys := []string{"agent", "ebpf", "correlation", "detection", "whitelist", "enrichment", "forensics", "output", "outputs", "api"}
		moved := 0
		for _, k := range legacyKeys {
			if v, ok := cfg[k]; ok {
				rsbp[k] = v
				delete(cfg, k)
				moved++
			}
		}
		if moved == 0 {
			return nil, nil, fmt.Errorf("invalid config: missing 'rsbp' section and no legacy top-level keys detected")
		}
		warnings = append(warnings, "detected legacy top-level config; wrapped into rsbp")
	}

	if outLegacy, ok := rsbp["output"]; ok {
		if _, has := rsbp["outputs"]; !has {
			rsbp["outputs"] = outLegacy
			warnings = append(warnings, "mapped rsbp.output -> rsbp.outputs")
		}
		delete(rsbp, "output")
	}

	if apiMap, ok := asMap(rsbp["api"]); ok {
		if listenAddr, hasListenAddr := apiMap["listen_addr"]; hasListenAddr {
			if _, hasListen := apiMap["listen"]; !hasListen {
				apiMap["listen"] = listenAddr
				warnings = append(warnings, "mapped rsbp.api.listen_addr -> rsbp.api.listen")
			}
			delete(apiMap, "listen_addr")
		}
		rsbp["api"] = apiMap
	}

	if detMap, ok := asMap(rsbp["detection"]); ok {
		if baselinePath, has := detMap["baseline_path"]; has {
			if _, hasNew := detMap["baseline_file"]; !hasNew {
				detMap["baseline_file"] = baselinePath
				warnings = append(warnings, "mapped rsbp.detection.baseline_path -> rsbp.detection.baseline_file")
			}
			delete(detMap, "baseline_path")
		}
		if _, hasScore := detMap["score_threshold"]; !hasScore {
			if v, ok := detMap["score_threshold_high"]; ok {
				detMap["score_threshold"] = v
				warnings = append(warnings, "mapped rsbp.detection.score_threshold_high -> rsbp.detection.score_threshold")
			} else if v, ok := detMap["score_threshold_medium"]; ok {
				detMap["score_threshold"] = v
				warnings = append(warnings, "mapped rsbp.detection.score_threshold_medium -> rsbp.detection.score_threshold")
			}
		}
		delete(detMap, "score_threshold_critical")
		delete(detMap, "score_threshold_high")
		delete(detMap, "score_threshold_medium")
		rsbp["detection"] = detMap
	}

	if enrichMap, ok := asMap(rsbp["enrichment"]); ok {
		if geo, hasGeo := enrichMap["geoip_db_path"]; hasGeo {
			if _, hasCity := enrichMap["geoip_db_city"]; !hasCity {
				enrichMap["geoip_db_city"] = geo
				warnings = append(warnings, "mapped rsbp.enrichment.geoip_db_path -> rsbp.enrichment.geoip_db_city")
			}
			delete(enrichMap, "geoip_db_path")
		}
		rsbp["enrichment"] = enrichMap
	}

	cfg["rsbp"] = rsbp

	if ver == 1 {
		cfg["config_version"] = strconv.Itoa(currentConfigVersion)
		warnings = append(warnings, "migrated config_version 1 -> 2")
		ver = currentConfigVersion
	}
	if ver != currentConfigVersion {
		return nil, nil, fmt.Errorf("unsupported config_version=%d (supported: %d)", ver, currentConfigVersion)
	}

	return cfg, warnings, nil
}

type appliedDefault struct {
	Field string
	Value any
}

func injectDefaults(cfg *appConfig, normalized map[string]any) []appliedDefault {
	defaults := make([]appliedDefault, 0, 16)

	if strings.TrimSpace(cfg.ConfigVersion) == "" {
		cfg.ConfigVersion = strconv.Itoa(currentConfigVersion)
		defaults = append(defaults, appliedDefault{Field: "config_version", Value: cfg.ConfigVersion})
	}

	if !hasPath(normalized, "rsbp.agent.log_level") || strings.TrimSpace(cfg.RSBP.Agent.LogLevel) == "" {
		cfg.RSBP.Agent.LogLevel = "info"
		defaults = append(defaults, appliedDefault{Field: "rsbp.agent.log_level", Value: "info"})
	}
	if !hasPath(normalized, "rsbp.agent.pid_file") || strings.TrimSpace(cfg.RSBP.Agent.PIDFile) == "" {
		cfg.RSBP.Agent.PIDFile = "/var/run/rsbp.pid"
		defaults = append(defaults, appliedDefault{Field: "rsbp.agent.pid_file", Value: "/var/run/rsbp.pid"})
	}

	if !hasPath(normalized, "rsbp.detection.window_seconds") || cfg.RSBP.Detection.WindowSeconds == 0 {
		cfg.RSBP.Detection.WindowSeconds = 5
		defaults = append(defaults, appliedDefault{Field: "rsbp.detection.window_seconds", Value: 5})
	}
	if !hasPath(normalized, "rsbp.detection.score_threshold") || cfg.RSBP.Detection.ScoreThreshold == 0 {
		cfg.RSBP.Detection.ScoreThreshold = 0.75
		defaults = append(defaults, appliedDefault{Field: "rsbp.detection.score_threshold", Value: 0.75})
	}
	if !hasPath(normalized, "rsbp.detection.allow_private_remote") {
		cfg.RSBP.Detection.AllowPrivateRemote = true
		defaults = append(defaults, appliedDefault{Field: "rsbp.detection.allow_private_remote", Value: true})
	}
	if !hasPath(normalized, "rsbp.detection.enable_baseline") {
		cfg.RSBP.Detection.EnableBaseline = true
		defaults = append(defaults, appliedDefault{Field: "rsbp.detection.enable_baseline", Value: true})
	}
	if !hasPath(normalized, "rsbp.detection.baseline_file") || strings.TrimSpace(cfg.RSBP.Detection.BaselineFile) == "" {
		cfg.RSBP.Detection.BaselineFile = "/var/lib/rsbp/baseline.json"
		defaults = append(defaults, appliedDefault{Field: "rsbp.detection.baseline_file", Value: "/var/lib/rsbp/baseline.json"})
	}

	if !hasPath(normalized, "rsbp.outputs.jsonl.enabled") {
		cfg.RSBP.Outputs.JSONL.Enabled = true
		defaults = append(defaults, appliedDefault{Field: "rsbp.outputs.jsonl.enabled", Value: true})
	}
	if !hasPath(normalized, "rsbp.outputs.jsonl.path") || strings.TrimSpace(cfg.RSBP.Outputs.JSONL.Path) == "" {
		cfg.RSBP.Outputs.JSONL.Path = "/var/log/rsbp/alerts.jsonl"
		defaults = append(defaults, appliedDefault{Field: "rsbp.outputs.jsonl.path", Value: "/var/log/rsbp/alerts.jsonl"})
	}

	if !hasPath(normalized, "rsbp.api.enabled") {
		cfg.RSBP.API.Enabled = true
		defaults = append(defaults, appliedDefault{Field: "rsbp.api.enabled", Value: true})
	}
	if !hasPath(normalized, "rsbp.api.listen") || strings.TrimSpace(cfg.RSBP.API.Listen) == "" {
		cfg.RSBP.API.Listen = "127.0.0.1:9001"
		defaults = append(defaults, appliedDefault{Field: "rsbp.api.listen", Value: "127.0.0.1:9001"})
	}
	if !hasPath(normalized, "rsbp.api.metrics_listen") || strings.TrimSpace(cfg.RSBP.API.MetricsListen) == "" {
		cfg.RSBP.API.MetricsListen = "0.0.0.0:9090"
		defaults = append(defaults, appliedDefault{Field: "rsbp.api.metrics_listen", Value: "0.0.0.0:9090"})
	}

	return defaults
}

func validateConfig(cfg *appConfig) error {
	issues := make([]string, 0, 16)

	configVersion, ok := parseInt(cfg.ConfigVersion)
	if !ok || configVersion != currentConfigVersion {
		issues = append(issues, fmt.Sprintf("config_version must be %d", currentConfigVersion))
	}

	if cfg.RSBP.Detection.WindowSeconds <= 0 || cfg.RSBP.Detection.WindowSeconds > 3600 {
		issues = append(issues, "rsbp.detection.window_seconds must be between 1 and 3600")
	}
	if cfg.RSBP.Detection.ScoreThreshold < 0 || cfg.RSBP.Detection.ScoreThreshold > 1 {
		issues = append(issues, "rsbp.detection.score_threshold must be between 0 and 1")
	}

	if cfg.RSBP.API.Enabled {
		if err := validateListenAddr("rsbp.api.listen", cfg.RSBP.API.Listen); err != nil {
			issues = append(issues, err.Error())
		}
	}
	if strings.TrimSpace(cfg.RSBP.API.MetricsListen) != "" {
		if err := validateListenAddr("rsbp.api.metrics_listen", cfg.RSBP.API.MetricsListen); err != nil {
			issues = append(issues, err.Error())
		}
	}

	if cfg.RSBP.Outputs.JSONL.Enabled {
		if strings.TrimSpace(cfg.RSBP.Outputs.JSONL.Path) == "" {
			issues = append(issues, "rsbp.outputs.jsonl.path is required when jsonl output is enabled")
		} else {
			if err := validateParentDirExists("rsbp.outputs.jsonl.path", cfg.RSBP.Outputs.JSONL.Path); err != nil {
				issues = append(issues, err.Error())
			}
		}
	}

	if cfg.RSBP.Detection.EnableBaseline && strings.TrimSpace(cfg.RSBP.Detection.BaselineFile) != "" {
		if err := validateParentDirExists("rsbp.detection.baseline_file", cfg.RSBP.Detection.BaselineFile); err != nil {
			issues = append(issues, err.Error())
		}
	}

	if cfg.RSBP.Forensics.Enabled {
		if strings.TrimSpace(cfg.RSBP.Forensics.OutputDir) == "" {
			issues = append(issues, "rsbp.forensics.output_dir is required when forensics is enabled")
		} else if err := validateDirExists("rsbp.forensics.output_dir", cfg.RSBP.Forensics.OutputDir); err != nil {
			issues = append(issues, err.Error())
		}
	}

	for i, entry := range cfg.RSBP.Whitelist.IPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				issues = append(issues, fmt.Sprintf("rsbp.whitelist.ips[%d] invalid CIDR: %s", i, entry))
			}
			continue
		}
		if net.ParseIP(entry) == nil {
			issues = append(issues, fmt.Sprintf("rsbp.whitelist.ips[%d] invalid IP: %s", i, entry))
		}
	}

	for i, p := range cfg.RSBP.Whitelist.Paths {
		pathValue := strings.TrimSpace(p)
		if pathValue == "" {
			issues = append(issues, fmt.Sprintf("rsbp.whitelist.paths[%d] must not be empty", i))
		}
	}

	if city := strings.TrimSpace(cfg.RSBP.Enrichment.GeoIPDBCity); city != "" {
		if _, err := os.Stat(city); err != nil {
			issues = append(issues, fmt.Sprintf("rsbp.enrichment.geoip_db_city file does not exist: %s", city))
		}
	}
	if asn := strings.TrimSpace(cfg.RSBP.Enrichment.GeoIPDBASN); asn != "" {
		if _, err := os.Stat(asn); err != nil {
			issues = append(issues, fmt.Sprintf("rsbp.enrichment.geoip_db_asn file does not exist: %s", asn))
		}
	}

	for i, addr := range cfg.RSBP.Outputs.Elasticsearch.Addresses {
		trimmed := strings.TrimSpace(addr)
		if trimmed == "" {
			issues = append(issues, fmt.Sprintf("rsbp.outputs.elasticsearch.addresses[%d] must not be empty", i))
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil || u.Scheme == "" || u.Host == "" {
			issues = append(issues, fmt.Sprintf("rsbp.outputs.elasticsearch.addresses[%d] invalid URL: %s", i, trimmed))
		}
	}

	if key := strings.TrimSpace(cfg.RSBP.Enrichment.AbuseIPDBAPIKey); key != "" && !apiKeyPattern.MatchString(key) {
		issues = append(issues, "rsbp.enrichment.abuseipdb_api_key format is invalid")
	}
	if cfg.RSBP.Outputs.Splunk.Enabled {
		token := strings.TrimSpace(cfg.RSBP.Outputs.Splunk.Token)
		if token == "" || !apiKeyPattern.MatchString(token) {
			issues = append(issues, "rsbp.outputs.splunk.token format is invalid")
		}
	}
	if cfg.RSBP.Outputs.Webhook.Enabled {
		if strings.TrimSpace(cfg.RSBP.Outputs.Webhook.URL) == "" {
			issues = append(issues, "rsbp.outputs.webhook.url is required when webhook output is enabled")
		}
		if secret := strings.TrimSpace(cfg.RSBP.Outputs.Webhook.Secret); secret == "" || len(secret) < 8 {
			issues = append(issues, "rsbp.outputs.webhook.secret must be at least 8 characters")
		}
	}
	if strings.TrimSpace(cfg.RSBP.Outputs.Syslog.Address) != "" {
		if err := validateHostPort("rsbp.outputs.syslog.address", cfg.RSBP.Outputs.Syslog.Address); err != nil {
			issues = append(issues, err.Error())
		}
	}

	if len(issues) > 0 {
		sort.Strings(issues)
		return fmt.Errorf("config validation failed:\n- %s", strings.Join(issues, "\n- "))
	}

	return nil
}

func resolveConfigValidationMode() configValidationMode {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("RSBP_ENV")))
	switch env {
	case "prod", "production":
		return configValidationModeProd
	default:
		return configValidationModeDev
	}
}

func validateAndPruneWhitelistPaths(paths []string, mode configValidationMode, logger *zap.Logger) whitelistPathValidationResult {
	result := whitelistPathValidationResult{
		ValidPaths:         make([]string, 0, len(paths)),
		RemovedPaths:       make([]string, 0),
		MissingPaths:       make([]string, 0),
		SkippedPatternPath: make([]string, 0),
	}

	for _, raw := range paths {
		pathValue := strings.TrimSpace(raw)
		if pathValue == "" {
			continue
		}

		if strings.ContainsAny(pathValue, "*?[]") {
			result.ValidPaths = append(result.ValidPaths, pathValue)
			result.SkippedPatternPath = append(result.SkippedPatternPath, pathValue)
			logger.Info("whitelist pattern path kept without existence check", zap.String("path", pathValue))
			continue
		}

		if _, err := os.Stat(pathValue); err != nil {
			result.RemovedPaths = append(result.RemovedPaths, pathValue)
			result.MissingPaths = append(result.MissingPaths, pathValue)
			if mode == configValidationModeDev {
				logger.Warn("whitelist path missing in dev mode; skipping entry", zap.String("path", pathValue), zap.Error(err))
				logger.Warn("Removed invalid path: " + pathValue)
			} else {
				logger.Error("whitelist path missing in production mode", zap.String("path", pathValue), zap.Error(err))
			}
			continue
		}

		result.ValidPaths = append(result.ValidPaths, pathValue)
		logger.Info("whitelist path validated", zap.String("path", pathValue))
	}

	logger.Info("whitelist path scan complete",
		zap.String("mode", string(mode)),
		zap.Int("valid_paths", len(result.ValidPaths)),
		zap.Int("removed_paths", len(result.RemovedPaths)),
	)

	return result
}

func newWhitelistMissingPathsError(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	return fmt.Errorf("config validation failed:\n- missing whitelist paths in production: %s\n- fix: remove these entries from rsbp.whitelist.paths or install the missing binaries", strings.Join(sorted, ", "))
}

func validateListenAddr(field string, addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("%s is required", field)
	}
	return validateHostPort(field, addr)
}

func validateHostPort(field string, value string) error {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be in host:port format: %w", field, err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if net.ParseIP(host) == nil && host != "localhost" {
		if strings.ContainsAny(host, " ") {
			return fmt.Errorf("%s has invalid host: %s", field, host)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s has invalid port: %s", field, portStr)
	}
	return nil
}

func validateParentDirExists(field string, filePath string) error {
	parent := filepath.Dir(filePath)
	if parent == "." || parent == "" {
		return fmt.Errorf("%s has invalid path: %s", field, filePath)
	}
	st, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("%s parent directory does not exist: %s", field, parent)
	}
	if !st.IsDir() {
		return fmt.Errorf("%s parent is not a directory: %s", field, parent)
	}
	return nil
}

func validateDirExists(field string, dirPath string) error {
	st, err := os.Stat(dirPath)
	if err != nil {
		return fmt.Errorf("%s directory does not exist: %s", field, dirPath)
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory: %s", field, dirPath)
	}
	return nil
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func parseInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func deepCopyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case map[string]any:
			out[k] = deepCopyMap(t)
		case []any:
			clone := make([]any, len(t))
			for i := range t {
				if nested, ok := t[i].(map[string]any); ok {
					clone[i] = deepCopyMap(nested)
				} else {
					clone[i] = t[i]
				}
			}
			out[k] = clone
		default:
			out[k] = v
		}
	}
	return out
}

func hasPath(root map[string]any, dotPath string) bool {
	parts := strings.Split(dotPath, ".")
	cur := root
	for i, p := range parts {
		v, ok := cur[p]
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		next, ok := v.(map[string]any)
		if !ok {
			return false
		}
		cur = next
	}
	return false
}
