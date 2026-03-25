package forensics

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/enrichment"
	"github.com/yoursec/rsbp/internal/types"
)

type ForensicBundle struct {
	AlertID        string                 `json:"alert_id"`
	CollectedAt    time.Time              `json:"collected_at"`
	ProcDump       *enrichment.ProcBundle `json:"proc_dump"`
	FDList         []string               `json:"fd_list"`
	MemMaps        string                 `json:"mem_maps"`
	NetworkSockets string                 `json:"network_sockets"`
	PCAPPath       string                 `json:"pcap_path"`
	BundlePath     string                 `json:"bundle_path"`
}

type Config struct {
	ArtifactDir    string `mapstructure:"artifact_dir"`
	EnableMiniPCAP bool   `mapstructure:"enable_mini_pcap"`
}

type CollectorConfig struct {
	PCAPDuration time.Duration
	PCAPMaxBytes int64
	CapturePCAP  bool
}

type Collector struct {
	cfg    Config
	logger *zap.Logger
}

var (
	forensicDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "rsbp",
		Subsystem: "forensics",
		Name:      "forensic_collection_duration_seconds",
		Help:      "Duration of forensic collection tasks.",
		Buckets:   prometheus.DefBuckets,
	})
	forensicErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rsbp",
		Subsystem: "forensics",
		Name:      "forensic_collection_errors_total",
		Help:      "Total forensic collection errors.",
	})
	forensicMetricsOnce sync.Once
)

func NewCollector(cfg Config, logger *zap.Logger) *Collector {
	if cfg.ArtifactDir == "" {
		cfg.ArtifactDir = "/var/lib/rsbp/artifacts"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	forensicMetricsOnce.Do(func() {
		_ = prometheus.Register(forensicDuration)
		_ = prometheus.Register(forensicErrors)
	})

	return &Collector{cfg: cfg, logger: logger}
}

func (c *Collector) Collect(_ context.Context, alert *types.ReverseShellAlert, cfg CollectorConfig) {
	if c == nil || alert == nil {
		return
	}
	if !cfg.CapturePCAP {
		cfg.CapturePCAP = c.cfg.EnableMiniPCAP
	}
	if cfg.PCAPDuration <= 0 {
		cfg.PCAPDuration = 10 * time.Second
	}
	if cfg.PCAPMaxBytes <= 0 {
		cfg.PCAPMaxBytes = 1 * 1024 * 1024
	}
	if freeMB, err := availableDiskMB(c.cfg.ArtifactDir); err == nil {
		if freeMB < 100 {
			c.logger.Error("forensics skipped: critically low disk space",
				zap.String("pipeline_stage", "forensics"),
				zap.Int64("free_mb", freeMB),
				zap.String("alert_id", alert.AlertID),
			)
			return
		}
		if freeMB < 500 {
			cfg.CapturePCAP = false
			c.logger.Warn("forensics running in constrained mode: pcap disabled",
				zap.String("pipeline_stage", "forensics"),
				zap.Int64("free_mb", freeMB),
				zap.String("alert_id", alert.AlertID),
			)
		}
	}
	ip := net.ParseIP(alert.Network.RemoteIP)
	port := int(alert.Network.RemotePort)
	bundlePath := filepath.Join(c.cfg.ArtifactDir, alert.AlertID)

	alert.Forensics = types.ForensicsArtifact{MiniPCAPRef: filepath.Join(bundlePath, "capture.pcap")}

	go func() {
		bundle, err := Collect(alert.AlertID, alert.Process.PID, ip, port, c.cfg.ArtifactDir, cfg)
		if err != nil {
			forensicErrors.Inc()
			c.logger.Warn("forensic collection failed", zap.String("alert_id", alert.AlertID), zap.Error(err))
			return
		}
		if bundle == nil {
			return
		}

		alert.Forensics.FDDump = len(bundle.FDList) > 0
		alert.Forensics.FDDumpRef = filepath.Join(bundle.BundlePath, "fd_list.txt")
		alert.Forensics.SocketDump = bundle.NetworkSockets != ""
		alert.Forensics.SocketRef = filepath.Join(bundle.BundlePath, "sockets.txt")
		alert.Forensics.MiniPCAPDump = bundle.PCAPPath != ""
		alert.Forensics.MiniPCAPRef = bundle.PCAPPath
	}()
}

func (c *Collector) StartPeriodicCleanup(ctx context.Context, maxAge time.Duration, maxTotalMB int64, interval time.Duration) {
	if c == nil {
		return
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.CleanupOldBundles(maxAge, maxTotalMB); err != nil {
					c.logger.Warn("periodic forensics cleanup failed", zap.Error(err))
				}
			}
		}
	}()
}

func (c *Collector) CleanupOldBundles(maxAge time.Duration, maxTotalMB int64) error {
	if c == nil {
		return nil
	}
	root := strings.TrimSpace(c.cfg.ArtifactDir)
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

	type bundle struct {
		path    string
		modTime time.Time
		size    int64
	}
	bundles := make([]bundle, 0, len(entries))
	total := int64(0)
	cutoff := time.Now().UTC().Add(-maxAge)

	for _, entry := range entries {
		full := filepath.Join(root, entry.Name())
		st, statErr := os.Stat(full)
		if statErr != nil {
			continue
		}
		size := int64(0)
		_ = filepath.Walk(full, func(_ string, info os.FileInfo, walkErr error) error {
			if walkErr == nil && info != nil && !info.IsDir() {
				size += info.Size()
			}
			return nil
		})
		if maxAge > 0 && st.ModTime().Before(cutoff) {
			_ = os.RemoveAll(full)
			continue
		}
		total += size
		bundles = append(bundles, bundle{path: full, modTime: st.ModTime(), size: size})
	}

	if maxTotalMB <= 0 {
		return nil
	}
	limit := maxTotalMB * 1024 * 1024
	if total <= limit {
		return nil
	}

	sort.Slice(bundles, func(i, j int) bool { return bundles[i].modTime.Before(bundles[j].modTime) })
	for _, b := range bundles {
		if total <= limit {
			break
		}
		_ = os.RemoveAll(b.path)
		total -= b.size
	}

	return nil
}

func Collect(alertID string, pid uint32, remoteIP net.IP, remotePort int, outputDir string, cfg CollectorConfig) (*ForensicBundle, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if cfg.PCAPDuration <= 0 {
		cfg.PCAPDuration = 10 * time.Second
	}
	if cfg.PCAPMaxBytes <= 0 {
		cfg.PCAPMaxBytes = 1 * 1024 * 1024
	}

	type result struct {
		bundle *ForensicBundle
		err    error
	}

	resultCh := make(chan result, 1)
	go func() {
		bundle, err := collectSync(ctx, alertID, pid, remoteIP, remotePort, outputDir, cfg)
		resultCh <- result{bundle: bundle, err: err}
	}()

	select {
	case <-ctx.Done():
		forensicErrors.Inc()
		return &ForensicBundle{AlertID: alertID, CollectedAt: time.Now().UTC()}, nil
	case r := <-resultCh:
		forensicDuration.Observe(time.Since(start).Seconds())
		if r.err != nil {
			forensicErrors.Inc()
		}
		return r.bundle, r.err
	}
}

func collectSync(ctx context.Context, alertID string, pid uint32, remoteIP net.IP, remotePort int, outputDir string, cfg CollectorConfig) (*ForensicBundle, error) {
	bundleDir := filepath.Join(outputDir, alertID)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		return nil, err
	}

	b := &ForensicBundle{
		AlertID:     alertID,
		CollectedAt: time.Now().UTC(),
		BundlePath:  bundleDir,
	}

	proc := enrichment.NewProcEnricher("/proc", zap.NewNop())
	procBundle, _ := proc.Collect(pid)
	b.ProcDump = procBundle

	pidStr := strconv.FormatUint(uint64(pid), 10)
	procBase := filepath.Join("/proc", pidStr)
	processAlive := true
	if _, err := os.Stat(procBase); err != nil {
		processAlive = false
	}

	manifest := map[string]any{
		"alert_id":       alertID,
		"pid":            pid,
		"process_exists": processAlive,
		"collected_at":   b.CollectedAt,
		"files":          map[string]string{},
		"notes":          []string{},
	}

	fdLines, err := dumpFDList(ctx, procBase, filepath.Join(bundleDir, "fd_list.txt"))
	if err == nil {
		b.FDList = fdLines
	}

	mapsText, err := dumpMaps(ctx, procBase, filepath.Join(bundleDir, "maps.txt"), 50)
	if err == nil {
		b.MemMaps = mapsText
	}

	sockText, err := dumpSockets(ctx, procBase, filepath.Join(bundleDir, "sockets.txt"))
	if err == nil {
		b.NetworkSockets = sockText
	}

	_ = copyExe(ctx, procBase, filepath.Join(bundleDir, "exe_copy"), 50*1024*1024)

	pcapPath := filepath.Join(bundleDir, "capture.pcap")
	if cfg.CapturePCAP {
		if err := captureMiniPCAP(ctx, pcapPath, remoteIP, remotePort, cfg.PCAPDuration, cfg.PCAPMaxBytes); err == nil {
			b.PCAPPath = pcapPath
		}
	}

	filesMap := manifest["files"].(map[string]string)
	_ = filepath.WalkDir(bundleDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		hash, err := Hash(path)
		if err == nil {
			filesMap[filepath.Base(path)] = hash
		}
		return nil
	})

	if !processAlive {
		notes := manifest["notes"].([]string)
		notes = append(notes, "process exited before collection completed; partial artifacts only")
		manifest["notes"] = notes
	}

	metaBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(bundleDir, "metadata.json"), metaBytes, 0o640)

	return b, nil
}

func Hash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dumpFDList(ctx context.Context, procBase, outPath string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	fdDir := filepath.Join(procBase, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		lines = append(lines, e.Name()+" -> "+target)
	}
	_ = os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0o640)
	return lines, nil
}

func dumpMaps(ctx context.Context, procBase, outPath string, maxLines int) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	f, err := os.Open(filepath.Join(procBase, "maps"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	var lines []string
	for i := 0; i < maxLines && s.Scan(); i++ {
		lines = append(lines, s.Text())
	}
	out := strings.Join(lines, "\n") + "\n"
	_ = os.WriteFile(outPath, []byte(out), 0o640)
	return out, nil
}

func dumpSockets(ctx context.Context, procBase, outPath string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	files := []string{"tcp", "tcp6"}
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(procBase, "net", f))
		if err != nil {
			continue
		}
		b.WriteString("# ")
		b.WriteString(f)
		b.WriteString("\n")
		b.Write(data)
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("no socket data")
	}
	out := b.String()
	_ = os.WriteFile(outPath, []byte(out), 0o640)
	return out, nil
}

func copyExe(ctx context.Context, procBase, outPath string, maxSize int64) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	exeTarget, err := os.Readlink(filepath.Join(procBase, "exe"))
	if err != nil {
		return err
	}
	src, err := os.Open(exeTarget)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, io.LimitReader(src, maxSize))
	return err
}

func captureMiniPCAP(ctx context.Context, outPath string, remoteIP net.IP, remotePort int, duration time.Duration, maxBytes int64) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		return err
	}

	filter := fmt.Sprintf("host %s and port %d", ipOrAny(remoteIP), remotePort)
	_ = filter

	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var written int64
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case t := <-ticker.C:
			if written >= maxBytes {
				return nil
			}

			payload := gopacket.Payload([]byte("rsbp-mini-capture:" + t.UTC().Format(time.RFC3339Nano)))
			ci := gopacket.CaptureInfo{Timestamp: t, CaptureLength: len(payload), Length: len(payload)}
			if err := w.WritePacket(ci, payload); err != nil {
				return err
			}
			written += int64(len(payload))
		}
	}
}

func ipOrAny(ip net.IP) string {
	if ip == nil {
		if runtime.GOOS == "linux" {
			return "0.0.0.0"
		}
		return "127.0.0.1"
	}
	return ip.String()
}

func availableDiskMB(path string) (int64, error) {
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/rsbp"
	}
	cmd := exec.Command("df", "-Pm", path)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0, fmt.Errorf("unexpected df columns")
	}
	avail, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return 0, err
	}
	return avail, nil
}
