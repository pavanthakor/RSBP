package correlation

import (
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProcessNode struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	ExePath   string    `json:"exe_path"`
	StartTime time.Time `json:"start_time"`
}

type SessionState struct {
	PID             uint32        `json:"pid"`
	PPID            uint32        `json:"ppid"`
	UID             uint32        `json:"uid"`
	GID             uint32        `json:"gid"`
	ExePath         string        `json:"exe_path"`
	Cmdline         string        `json:"cmdline"`
	SocketFD        int32         `json:"socket_fd"`
	RemoteIP        net.IP        `json:"remote_ip"`
	RemotePort      uint16        `json:"remote_port"`
	HasExecve       bool          `json:"has_execve"`
	HasSocket       bool          `json:"has_socket"`
	HasConnect      bool          `json:"has_connect"`
	HasDupToStdio   bool          `json:"has_dup_to_stdio"`
	HasForkWithPipe bool          `json:"has_fork_with_pipe"`
	StartTime       time.Time     `json:"start_time"`
	LastUpdate      time.Time     `json:"last_update"`
	Category        int           `json:"category"`
	ProcessTree     []ProcessNode `json:"process_tree"`
	FirstEventAt    time.Time     `json:"first_event_at"`
}

var ShellBinaries = map[string]struct{}{
	"bash":             {},
	"sh":               {},
	"zsh":              {},
	"dash":             {},
	"ksh":              {},
	"fish":             {},
	"python":           {},
	"python3":          {},
	"perl":             {},
	"ruby":             {},
	"nc":               {},
	"ncat":             {},
	"ncat.traditional": {},
	"netcat":           {},
	"socat":            {},
	"busybox":          {},
	"awk":              {},
	"lua":              {},
	"php":              {},
	"node":             {},
	"nodejs":           {},
}

var allowPrivateRemoteFlag atomic.Bool

var builtInProcessWhitelist = map[string]struct{}{
	"curl":                {},
	"grafana":             {},
	"filebeat":            {},
	"elasticsearch":       {},
	"kibana":              {},
	"rsbpd":               {},
	"dockerd":             {},
	"docker":              {},
	"containerd":          {},
	"runc":                {},
	"node":                {},
	"systemd":             {},
	"systemd-resolved":    {},
	"systemd-timesyncd":   {},
	"systemd-logind":      {},
	"systemd-networkd":    {},
	"dbus-daemon":         {},
	"snapd":               {},
	"packagekitd":         {},
	"polkitd":             {},
	"agetty":              {},
	"cron":                {},
	"sshd":                {},
	"iptables":            {},
	"ip6tables":           {},
	"udevd":               {},
	"init":                {},
	"wsl-pro-service":     {},
	"wslgd":               {},
	"landscape-config":    {},
	"networkd-dispatcher": {},
	"plymouth":            {},
	"modprobe":            {},
	"kmod":                {},
	"e2scrub_all":         {},
	"apt-helper":          {},
	"mandb":               {},
	"find":                {},
	"install":             {},
	"journalctl":          {},
	"rpcbind":             {},
	"nfs-common":          {},
	"rpc.statd":           {},
	"containerd-shim":     {},
	"docker-init":         {},
	"fusermount":          {},
	"http":                {},
	"https":               {},
}

var reverseShellProcessExceptionSet = map[string]struct{}{
	"python3": {},
	"python":  {},
	"nc":      {},
	"netcat":  {},
	"ncat":    {},
	"dash":    {},
}

var builtInPathWhitelistContains = []string{
	"/usr/lib/systemd",
	"/lib/systemd",
	"/usr/libexec",
	"/usr/sbin/cron",
	"/usr/bin/dbus",
	"/snap/",
	"/usr/lib/apt",
	"/usr/lib/packagekit",
	"/usr/share/unattended",
	"/usr/sbin/agetty",
	"/usr/bin/plymouth",
	"/lib/ufw",
	"/sbin/modprobe",
	"/bin/kmod",
	"/bin/mount",
	"/bin/umount",
	"/usr/bin/find",
	"/usr/bin/install",
	"/usr/bin/mandb",
}

var builtInIgnoredCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
}

var builtInSafePorts = map[uint16]struct{}{
	53:  {},
	123: {},
	443: {},
}

var (
	builtInCIDROnce sync.Once
	builtInCIDRNets []*net.IPNet
)

func init() {
	allowPrivateRemoteFlag.Store(true)
}

func SetAllowPrivateRemote(allow bool) {
	allowPrivateRemoteFlag.Store(allow)
}

func IsShellBinary(name string) bool {
	if name == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	_, ok := ShellBinaries[base]
	return ok
}

func (s *SessionState) CategoryDetect() int {
	if s == nil {
		return 0
	}
	comm := strings.ToLower(strings.TrimSpace(s.ProcessName()))
	exeBase := strings.ToLower(filepath.Base(strings.TrimSpace(s.ExePath)))
	_, shellByComm := ShellBinaries[comm]
	_, shellByExe := ShellBinaries[exeBase]
	isShell := shellByComm || shellByExe

	if s.HasExecve && s.HasConnect {
		if isNetcatExe(s.ExePath) {
			return 1
		}
		if isShell && s.HasDupToStdio {
			return 1
		}
	}

	if s.HasForkWithPipe && s.HasDupToStdio && s.HasExecve {
		return 2
	}
	if s.HasForkWithPipe && s.HasExecve {
		return 3
	}

	return 0
}

func (s *SessionState) IsComplete() bool {
	if s == nil {
		return false
	}

	cat := s.CategoryDetect()
	s.Category = cat

	comm := strings.ToLower(strings.TrimSpace(s.ProcessName()))
	exeBase := strings.ToLower(filepath.Base(strings.TrimSpace(s.ExePath)))
	cmdlineLower := strings.ToLower(strings.TrimSpace(s.Cmdline))

	isRSToolName := func(n string) bool {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "bash", "sh", "python3", "python", "nc", "netcat", "ncat", "dash":
			return true
		default:
			return false
		}
	}

	// Identify known reverse shell tools via comm, exe basename, or cmdline.
	isRSTool := isRSToolName(comm) || isRSToolName(exeBase)
	if !isRSTool {
		for _, needle := range []string{"bash", "sh", "python3", "python", " netcat", " ncat", " nc ", "/dev/tcp"} {
			if strings.Contains(cmdlineLower, needle) {
				isRSTool = true
				break
			}
		}
	}

	// For most processes, require an observed execve; known reverse shell tools may
	// legitimately lack an execve in the correlation window (e.g. long-lived shells).
	if !s.HasExecve && !isRSTool {
		return false
	}

	if !s.HasConnect {
		return false
	}
	if s.RemoteIP == nil || s.RemoteIP.IsUnspecified() {
		return false
	}
	if s.RemotePort == 0 {
		return false
	}

	// Only enforce public-remote constraints for non-tools; reverse shell tools are
	// commonly tested against RFC1918 targets and the correlation layer focuses on
	// behavior rather than remote reputation.
	if !isRSTool && !allowPrivateRemoteFlag.Load() && !isPublicRemoteIP(s.RemoteIP) {
		return false
	}

	processName := s.ProcessName()

	// FIXED: skip built-in process/path whitelist checks entirely for known RS tools.
	if !isRSTool {
		if isBuiltInWhitelistedProcessName(processName) {
			return false
		}
		if isBuiltInWhitelistedPath(s.ExePath) {
			return false
		}
	}

	// FIXED: For RS tools, only block true loopback/unspecified; allow RFC1918 targets.
	if isRSTool {
		if isLoopbackIP(s.RemoteIP) {
			return false
		}
	} else {
		if isBuiltInWhitelistedIP(s.RemoteIP) {
			return false
		}
	}

	if isBuiltInSafePort(s.RemotePort) {
		return false
	}

	return true
}

func (s *SessionState) ProcessName() string {
	if s == nil {
		return ""
	}
	if len(s.ProcessTree) > 0 {
		name := strings.TrimSpace(s.ProcessTree[len(s.ProcessTree)-1].Comm)
		if name != "" {
			return strings.ToLower(name)
		}
	}
	if s.ExePath != "" {
		return strings.ToLower(filepath.Base(strings.TrimSpace(s.ExePath)))
	}
	return ""
}

func isBuiltInWhitelistedProcessName(name string) bool {
	_, ok := builtInProcessWhitelist[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func isBuiltInWhitelistedPath(exePath string) bool {
	clean := strings.ToLower(strings.TrimSpace(exePath))
	if clean == "" {
		return false
	}
	for _, marker := range builtInPathWhitelistContains {
		if strings.Contains(clean, marker) {
			return true
		}
	}
	return false
}

func isBuiltInWhitelistedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	builtInCIDROnce.Do(func() {
		builtInCIDRNets = make([]*net.IPNet, 0, len(builtInIgnoredCIDRs))
		for _, cidr := range builtInIgnoredCIDRs {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil && n != nil {
				builtInCIDRNets = append(builtInCIDRNets, n)
			}
		}
	})

	normalized := ip
	if v4 := ip.To4(); v4 != nil {
		normalized = v4
	}
	for _, n := range builtInCIDRNets {
		if n.Contains(normalized) {
			return true
		}
	}
	return false
}

func isLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

func isBuiltInSafePort(port uint16) bool {
	_, ok := builtInSafePorts[port]
	return ok
}

func isReverseShellProcessException(name string) bool {
	_, ok := reverseShellProcessExceptionSet[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func isReverseShellSessionException(s *SessionState) bool {
	if s == nil {
		return false
	}
	if isReverseShellProcessException(s.ProcessName()) {
		return true
	}
	if isReverseShellProcessException(filepath.Base(strings.ToLower(strings.TrimSpace(s.ExePath)))) {
		return true
	}
	for _, n := range s.ProcessTree {
		if isReverseShellProcessException(n.Comm) {
			return true
		}
	}
	return false
}

func isNetcatExe(exe string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(exe)))
	return strings.Contains(base, "nc") || strings.Contains(base, "ncat") || strings.Contains(base, "netcat")
}

func isPublicRemoteIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}

	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 10 {
			return false
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return false
		}
		if v4[0] == 192 && v4[1] == 168 {
			return false
		}
	}

	return true
}
