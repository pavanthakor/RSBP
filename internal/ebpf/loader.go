package ebpf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/types"
)

type Stats struct {
	EventsRead      uint64
	LostEvents      uint64
	AttachedProbes  int
	EventsPerSecond float64
	DroppedEvents   uint64
}

const (
	capSysAdminBit     = 21
	capBPFBit          = 39
	expectedProbeCount = 11
	sysExecve          = 59
	sysSocket          = 41
	sysConnect         = 42
	sysDup2            = 33
	sysDup3            = 292
	sysFork            = 57
	sysClone3          = 435
	sysPipe            = 22
	sysPipe2           = 293
)

var (
	probeNameRegexp = regexp.MustCompile(`name\s+(trace_[a-zA-Z0-9_]+)`)
	probeCountGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "rsbp",
		Subsystem: "ebpf",
		Name:      "probe_count",
		Help:      "Number of attached RSBP eBPF tracepoint programs observed by bpftool.",
	})
	probeGaugeOnce     sync.Once
	ebpfMetricsOnce    sync.Once
	eventsTotalCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "events_total",
		Help:      "Total decoded eBPF events by syscall type.",
	}, []string{"syscall_type"})
	eventsPerSecondGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "rsbp",
		Name:      "events_per_second",
		Help:      "Observed eBPF event throughput per second (5s moving update).",
	})
	ringBufferLostTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "ring_buffer_lost_total",
		Help:      "Total lost or undecodable ring buffer events.",
	})
	ebpfDropsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "ebpf_drops_total",
		Help:      "Total eBPF events dropped due to full userspace channel.",
	})
)

type RuntimeEnvironment struct {
	OS            string
	KernelRelease string
	IsLinux       bool
	IsWSL         bool
	IsContainer   bool
}

type PrivilegeReport struct {
	EffectiveMask  string
	HasCAPSYSADMIN bool
	HasCAPBPF      bool
	Missing        []string
}

type PrivilegeError struct {
	Missing       []string
	EffectiveMask string
}

func (e *PrivilegeError) Error() string {
	if e == nil {
		return "missing required capabilities"
	}
	if len(e.Missing) == 0 {
		return "missing required capabilities"
	}
	return fmt.Sprintf("missing required capabilities: %s", strings.Join(e.Missing, ", "))
}

func IsPrivilegeError(err error) bool {
	var pe *PrivilegeError
	return errors.As(err, &pe)
}

func PrivilegeErrorDetails(err error) (PrivilegeReport, bool) {
	var pe *PrivilegeError
	if !errors.As(err, &pe) || pe == nil {
		return PrivilegeReport{}, false
	}
	report := PrivilegeReport{
		EffectiveMask: pe.EffectiveMask,
		Missing:       append([]string(nil), pe.Missing...),
	}
	for _, capName := range pe.Missing {
		switch capName {
		case "CAP_SYS_ADMIN":
			report.HasCAPSYSADMIN = false
		case "CAP_BPF":
			report.HasCAPBPF = false
		}
	}
	return report, true
}

func DetectRuntimeEnvironment() RuntimeEnvironment {
	env := RuntimeEnvironment{
		OS:      runtime.GOOS,
		IsLinux: runtime.GOOS == "linux",
	}

	if !env.IsLinux {
		return env
	}

	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		env.KernelRelease = strings.TrimSpace(string(data))
	}

	lowerRelease := strings.ToLower(env.KernelRelease)
	if strings.Contains(lowerRelease, "microsoft") || strings.Contains(lowerRelease, "wsl") {
		env.IsWSL = true
	}
	if !env.IsWSL {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			v := strings.ToLower(string(data))
			if strings.Contains(v, "microsoft") || strings.Contains(v, "wsl") {
				env.IsWSL = true
			}
		}
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		env.IsContainer = true
	}
	if !env.IsContainer {
		if _, err := os.Stat("/run/.containerenv"); err == nil {
			env.IsContainer = true
		}
	}
	if !env.IsContainer {
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			cg := strings.ToLower(string(data))
			if strings.Contains(cg, "docker") || strings.Contains(cg, "containerd") || strings.Contains(cg, "kubepods") {
				env.IsContainer = true
			}
		}
	}

	return env
}

func DetectPrivileges() (PrivilegeReport, error) {
	report := PrivilegeReport{}
	if runtime.GOOS != "linux" {
		return report, nil
	}

	buf, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return report, err
	}
	data := string(buf)

	var capEffHex string
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				capEffHex = parts[1]
			}
			break
		}
	}
	if capEffHex == "" {
		return report, fmt.Errorf("failed to read CapEff from /proc/self/status")
	}

	val, err := strconv.ParseUint(capEffHex, 16, 64)
	if err != nil {
		return report, err
	}

	report.EffectiveMask = capEffHex
	report.HasCAPSYSADMIN = ((val >> capSysAdminBit) & 1) == 1
	report.HasCAPBPF = ((val >> capBPFBit) & 1) == 1

	missing := make([]string, 0, 2)
	if !report.HasCAPSYSADMIN {
		missing = append(missing, "CAP_SYS_ADMIN")
	}
	if !report.HasCAPBPF {
		missing = append(missing, "CAP_BPF")
	}
	report.Missing = missing

	return report, nil
}

type Loader struct {
	logger *zap.Logger

	coll     *ebpf.Collection
	reader   *ringbuf.Reader
	links    []link.Link
	linksMu  sync.RWMutex
	bootTime time.Time

	eventsRead              atomic.Uint64
	lostEvents              atomic.Uint64
	eventsPerSecondTimes100 atomic.Uint64
	ebpfDrops               atomic.Uint64

	closeOnce sync.Once
}

type rawSyscallEvent struct {
	PID            uint32
	PPID           uint32
	UID            uint32
	GID            uint32
	SyscallNr      uint32
	FD             int32
	RemoteIP4      uint32
	RemoteIP6      [16]byte
	RemotePort     uint16
	Family         uint16
	TimestampNS    uint64
	Comm           [16]byte
	ExecPath       [256]byte
	Args           [512]byte
	HasExecve      uint8
	HasSocket      uint8
	HasConnect     uint8
	HasDup2Stdio   uint8
	ForkParentPID  uint32
	SuspiciousMask uint32
}

func New(logger *zap.Logger) (*Loader, error) {
	if logger == nil {
		return nil, fmt.Errorf("ebpf loader: %w", fmt.Errorf("logger is nil"))
	}

	env := DetectRuntimeEnvironment()
	if env.IsWSL {
		logger.Warn("running on WSL; eBPF support can be limited depending on kernel and capabilities",
			zap.String("kernel_release", env.KernelRelease),
			zap.Bool("is_container", env.IsContainer),
			zap.String("hint", "prefer latest WSL2 kernel and run with CAP_BPF or CAP_SYS_ADMIN"),
		)
	}

	if err := ensureKernelVersion(); err != nil {
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}
	if err := ensurePrivileges(); err != nil {
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}

	var objs bpfObjects
	if err := withRetry("load_bpf_objects", logger, 3, 200*time.Millisecond, func() error {
		_ = objs.Close()
		return loadBpfObjects(&objs, nil)
	}); err != nil {
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}

	var spec *ebpf.CollectionSpec
	if err := withRetry("load_bpf_spec", logger, 3, 200*time.Millisecond, func() error {
		loaded, loadErr := loadBpf()
		if loadErr != nil {
			return loadErr
		}
		spec = loaded
		return nil
	}); err != nil {
		objs.Close()
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}

	var coll *ebpf.Collection
	if err := withRetry("create_bpf_collection", logger, 3, 250*time.Millisecond, func() error {
		created, createErr := ebpf.NewCollection(spec)
		if createErr != nil {
			return createErr
		}
		coll = created
		return nil
	}); err != nil {
		objs.Close()
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}

	var links []link.Link
	if err := withRetry("attach_tracepoints", logger, 3, 300*time.Millisecond, func() error {
		attached, attachErr := attachTracepoints(coll)
		if attachErr != nil {
			return attachErr
		}
		links = attached
		return nil
	}); err != nil {
		coll.Close()
		objs.Close()
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		for _, lnk := range links {
			_ = lnk.Close()
		}
		coll.Close()
		objs.Close()
		return nil, fmt.Errorf("ebpf loader: %w", fmt.Errorf("events map not found"))
	}

	var reader *ringbuf.Reader
	if err := withRetry("create_ring_buffer_reader", logger, 3, 300*time.Millisecond, func() error {
		created, createErr := ringbuf.NewReader(eventsMap)
		if createErr != nil {
			return createErr
		}
		reader = created
		return nil
	}); err != nil {
		for _, lnk := range links {
			_ = lnk.Close()
		}
		coll.Close()
		objs.Close()
		return nil, fmt.Errorf("ebpf loader: %w", err)
	}

	_ = objs.Close()
	probeGaugeOnce.Do(func() {
		_ = prometheus.Register(probeCountGauge)
	})
	ebpfMetricsOnce.Do(func() {
		_ = prometheus.Register(eventsTotalCounter)
		_ = prometheus.Register(eventsPerSecondGauge)
		_ = prometheus.Register(ringBufferLostTotal)
		_ = prometheus.Register(ebpfDropsTotal)
	})
	probeCountGauge.Set(float64(len(links)))

	return &Loader{
		logger:   logger,
		coll:     coll,
		reader:   reader,
		links:    links,
		bootTime: getBootTime(),
	}, nil
}

func (l *Loader) Run(ctx context.Context, events chan<- types.SyscallEvent) error {
	if l == nil {
		return fmt.Errorf("ebpf loader: %w", fmt.Errorf("loader is nil"))
	}
	if l.reader == nil {
		return fmt.Errorf("ebpf loader: %w", fmt.Errorf("reader is not initialized"))
	}

	errCh := make(chan error, 1)
	epsDone := make(chan struct{})
	go func() {
		defer close(epsDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		prev := l.eventsRead.Load()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				next := l.eventsRead.Load()
				delta := next - prev
				prev = next
				eps := float64(delta) / 5.0
				eventsPerSecondGauge.Set(eps)
				l.eventsPerSecondTimes100.Store(uint64(eps * 100))
			}
		}
	}()

	go func() {
		defer close(errCh)
		for {
			record, err := l.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("ebpf loader: %w", err)
				return
			}

			var raw rawSyscallEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
				l.lostEvents.Add(1)
				ringBufferLostTotal.Inc()
				l.logger.Warn("failed to decode raw sample", zap.Error(err))
				continue
			}

			syscallType := syscallType(raw.SyscallNr)
			eventsTotalCounter.WithLabelValues(syscallType).Inc()

			event := types.SyscallEvent{
				PID:            raw.PID,
				PPID:           raw.PPID,
				UID:            raw.UID,
				GID:            raw.GID,
				SyscallNr:      raw.SyscallNr,
				FD:             raw.FD,
				RemoteIP4:      raw.RemoteIP4,
				RemoteIP6:      raw.RemoteIP6,
				RemotePort:     raw.RemotePort,
				Family:         raw.Family,
				TimestampNS:    toUnixTimestampNS(l.bootTime, raw.TimestampNS),
				Comm:           raw.Comm,
				ExecPath:       raw.ExecPath,
				Args:           raw.Args,
				HasExecve:      raw.HasExecve,
				HasSocket:      raw.HasSocket,
				HasConnect:     raw.HasConnect,
				HasDup2Stdio:   raw.HasDup2Stdio,
				ForkParentPID:  raw.ForkParentPID,
				SuspiciousMask: raw.SuspiciousMask,
				ReceivedAt:     time.Now().UTC(),
			}

			comm := strings.ToLower(strings.TrimRight(string(event.Comm[:]), "\x00"))
			if comm == "bash" || comm == "sh" || comm == "python3" || comm == "nc" {
				l.logger.Info("DEBUG BPF EVENT",
					zap.String("pipeline_stage", "ebpf"),
					zap.Float64("latency_ms", float64(time.Since(event.ReceivedAt).Microseconds())/1000.0),
					zap.String("comm", comm),
					zap.Uint32("pid", event.PID),
					zap.Uint32("syscall_nr", event.SyscallNr),
					zap.Uint8("has_execve", event.HasExecve),
					zap.Uint8("has_socket", event.HasSocket),
					zap.Uint8("has_connect", event.HasConnect),
					zap.Uint8("has_dup2_stdio", event.HasDup2Stdio),
					zap.Uint32("remote_ip4", event.RemoteIP4),
					zap.Uint16("remote_port", event.RemotePort),
				)
			}

			l.logger.Info("EVENT RECEIVED",
				zap.String("pipeline_stage", "ebpf"),
				zap.Float64("latency_ms", float64(time.Since(event.ReceivedAt).Microseconds())/1000.0),
				zap.Uint32("pid", event.PID),
				zap.String("comm", strings.TrimRight(string(event.Comm[:]), "\x00")),
			)

			l.logger.Info("DEBUG SENDING TO CORRELATION",
				zap.String("pipeline_stage", "ebpf"),
				zap.Float64("latency_ms", float64(time.Since(event.ReceivedAt).Microseconds())/1000.0),
				zap.String("comm", comm),
				zap.Uint32("pid", event.PID),
			)

			select {
			case events <- event:
				l.eventsRead.Add(1)
			case <-ctx.Done():
				errCh <- nil
				return
			default:
				l.ebpfDrops.Add(1)
				ebpfDropsTotal.Inc()
				l.logger.Warn("event channel full, dropping eBPF event",
					zap.String("pipeline_stage", "ebpf"),
					zap.Float64("latency_ms", float64(time.Since(event.ReceivedAt).Microseconds())/1000.0),
					zap.Uint32("pid", event.PID),
					zap.Uint32("syscall_nr", event.SyscallNr),
				)
			}
		}
	}()

	select {
	case <-ctx.Done():
		if err := l.Close(); err != nil {
			return fmt.Errorf("ebpf loader: %w", err)
		}
		<-epsDone
		return nil
	case err := <-errCh:
		if closeErr := l.Close(); closeErr != nil && err == nil {
			return fmt.Errorf("ebpf loader: %w", closeErr)
		}
		<-epsDone
		if err != nil {
			return fmt.Errorf("ebpf loader: %w", err)
		}
		return nil
	}
}

func toUnixTimestampNS(bootTime time.Time, ktimeNS uint64) uint64 {
	if ktimeNS == 0 {
		return 0
	}
	if bootTime.IsZero() {
		bootTime = time.Now()
	}
	eventTime := bootTime.Add(time.Duration(ktimeNS))
	return uint64(eventTime.UnixNano())
}

func getBootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					btime, parseErr := strconv.ParseInt(fields[1], 10, 64)
					if parseErr == nil {
						return time.Unix(btime, 0)
					}
				}
			}
		}
	}
	return time.Now()
}

func (l *Loader) Close() error {
	if l == nil {
		return nil
	}

	var closeErr error
	l.closeOnce.Do(func() {
		if l.reader != nil {
			if err := l.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				closeErr = fmt.Errorf("ebpf loader: %w", err)
			}
		}

		l.linksMu.Lock()
		links := append([]link.Link(nil), l.links...)
		l.links = nil
		l.linksMu.Unlock()

		for _, lnk := range links {
			if lnk == nil {
				continue
			}
			if err := lnk.Close(); err != nil && closeErr == nil {
				closeErr = fmt.Errorf("ebpf loader: %w", err)
			}
		}

		if l.coll != nil {
			l.coll.Close()
		}
		probeCountGauge.Set(0)
	})

	return closeErr
}

func (l *Loader) Stats() Stats {
	if l == nil {
		return Stats{}
	}
	l.linksMu.RLock()
	attached := len(l.links)
	l.linksMu.RUnlock()
	return Stats{
		EventsRead:      l.eventsRead.Load(),
		LostEvents:      l.lostEvents.Load(),
		AttachedProbes:  attached,
		EventsPerSecond: float64(l.eventsPerSecondTimes100.Load()) / 100.0,
		DroppedEvents:   l.ebpfDrops.Load(),
	}
}

func syscallType(syscallNr uint32) string {
	switch syscallNr {
	case sysExecve:
		return "execve"
	case sysSocket:
		return "socket"
	case sysConnect:
		return "connect"
	case sysDup2, sysDup3:
		return "dup"
	case sysFork, sysClone3:
		return "fork"
	case sysPipe, sysPipe2:
		return "pipe"
	default:
		return "other"
	}
}

func (l *Loader) ProbeHealthCheck(ctx context.Context) {
	if l == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count, err := l.countAttachedProgramsViaBPFTool()
				if err != nil {
					l.logger.Warn("probe health check failed", zap.Error(err))
					l.linksMu.RLock()
					fallback := len(l.links)
					l.linksMu.RUnlock()
					probeCountGauge.Set(float64(fallback))
					continue
				}

				probeCountGauge.Set(float64(count))
				if count >= expectedProbeCount {
					continue
				}

				l.logger.Error("CRITICAL: eBPF probe count dropped below expected threshold; attempting re-attach",
					zap.Int("observed_probe_count", count),
					zap.Int("expected_probe_count", expectedProbeCount),
				)

				if err := l.reattachProbes(); err != nil {
					l.logger.Error("probe re-attach attempt failed", zap.Error(err))
					continue
				}

				l.linksMu.RLock()
				reattached := len(l.links)
				l.linksMu.RUnlock()
				probeCountGauge.Set(float64(reattached))
				l.logger.Info("probe re-attach completed", zap.Int("attached_probe_count", reattached))
			}
		}
	}()
}

func (l *Loader) countAttachedProgramsViaBPFTool() (int, error) {
	if l == nil {
		return 0, fmt.Errorf("loader is nil")
	}

	cmd := exec.Command("bpftool", "prog", "list")
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	matches := probeNameRegexp.FindAllStringSubmatch(string(out), -1)
	if len(matches) == 0 {
		return 0, nil
	}

	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := strings.TrimSpace(m[1])
		if strings.HasPrefix(name, "trace_") {
			seen[name] = struct{}{}
		}
	}

	return len(seen), nil
}

func (l *Loader) reattachProbes() error {
	if l == nil || l.coll == nil {
		return fmt.Errorf("loader collection is not initialized")
	}

	newLinks, err := attachTracepoints(l.coll)
	if err != nil {
		return err
	}

	l.linksMu.Lock()
	oldLinks := l.links
	l.links = newLinks
	l.linksMu.Unlock()

	for _, lnk := range oldLinks {
		if lnk != nil {
			_ = lnk.Close()
		}
	}

	return nil
}

func (l *Loader) ReattachProbes() error {
	if l == nil {
		return fmt.Errorf("loader is nil")
	}
	return l.reattachProbes()
}

func attachTracepoints(coll *ebpf.Collection) ([]link.Link, error) {
	bindings := []struct {
		program string
		group   string
		name    string
	}{
		{program: "trace_enter_execve", group: "syscalls", name: "sys_enter_execve"},
		{program: "trace_exit_execve", group: "syscalls", name: "sys_exit_execve"},
		{program: "trace_enter_socket", group: "syscalls", name: "sys_enter_socket"},
		{program: "trace_exit_socket", group: "syscalls", name: "sys_exit_socket"},
		{program: "trace_enter_connect", group: "syscalls", name: "sys_enter_connect"},
		{program: "trace_enter_dup2", group: "syscalls", name: "sys_enter_dup2"},
		{program: "trace_enter_dup3", group: "syscalls", name: "sys_enter_dup3"},
		{program: "trace_enter_fork", group: "syscalls", name: "sys_enter_fork"},
		{program: "trace_enter_clone3", group: "syscalls", name: "sys_enter_clone3"},
		{program: "trace_enter_pipe", group: "syscalls", name: "sys_enter_pipe"},
		{program: "trace_enter_pipe2", group: "syscalls", name: "sys_enter_pipe2"},
	}

	links := make([]link.Link, 0, len(bindings))
	for _, b := range bindings {
		prog, ok := coll.Programs[b.program]
		if !ok {
			for _, lnk := range links {
				_ = lnk.Close()
			}
			return nil, fmt.Errorf("missing program %s", b.program)
		}

		lnk, err := link.Tracepoint(b.group, b.name, prog, nil)
		if err != nil {
			for _, opened := range links {
				_ = opened.Close()
			}
			return nil, err
		}
		links = append(links, lnk)
	}

	return links, nil
}

func ensureKernelVersion() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return err
	}
	release := strings.TrimSpace(string(data))
	major, minor, err := parseKernelVersion(release)
	if err != nil {
		return err
	}

	if major < 5 || (major == 5 && minor < 8) {
		return fmt.Errorf("kernel %s is unsupported, require >= 5.8", release)
	}

	return nil
}

func ensurePrivileges() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	report, err := DetectPrivileges()
	if err != nil {
		return err
	}
	if report.HasCAPSYSADMIN || report.HasCAPBPF {
		return nil
	}
	return &PrivilegeError{Missing: report.Missing, EffectiveMask: report.EffectiveMask}
}

func withRetry(stage string, logger *zap.Logger, attempts int, baseDelay time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	if baseDelay <= 0 {
		baseDelay = 200 * time.Millisecond
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		if logger != nil {
			logger.Warn("ebpf initialization step failed; retrying",
				zap.String("stage", stage),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", attempts),
				zap.Error(err),
			)
		}
		time.Sleep(time.Duration(attempt) * baseDelay)
	}

	return fmt.Errorf("%s: %w", stage, lastErr)
}

func parseKernelVersion(release string) (int, int, error) {
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("invalid kernel release: %s", release)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}

	minorPart := parts[1]
	if idx := strings.IndexAny(minorPart, "-+"); idx >= 0 {
		minorPart = minorPart[:idx]
	}
	minor, err := strconv.Atoi(minorPart)
	if err != nil {
		return 0, 0, err
	}

	return major, minor, nil
}
