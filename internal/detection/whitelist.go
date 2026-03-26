package detection

import (
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/yoursec/rsbp/internal/correlation"
)

var defaultProcessWhitelist = []string{
	"curl",
	"grafana",
	"filebeat",
	"elasticsearch",
	"kibana",
	"rsbpd",
	"dockerd",
	"docker",
	"containerd",
	"runc",
	"node",
	"systemd",
	"systemd-resolved",
	"systemd-timesyncd",
	"systemd-logind",
	"systemd-networkd",
	"dbus-daemon",
	"snapd",
	"packagekitd",
	"polkitd",
	"agetty",
	"cron",
	"sshd",
	"iptables",
	"ip6tables",
	"udevd",
	"init",
	"wsl-pro-service",
	"wslgd",
	"landscape-config",
	"networkd-dispatcher",
	"plymouth",
	"modprobe",
	"kmod",
	"e2scrub_all",
	"apt-helper",
	"mandb",
	"find",
	"install",
	"journalctl",
	"rpcbind",
	"nfs-common",
	"rpc.statd",
	"containerd-shim",
	"docker-init",
	"fusermount",
	"http",
	"https",
}

var defaultPathWhitelistContains = []string{
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

var defaultIgnoredCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
}

var defaultSafePorts = map[uint16]struct{}{
	53:  {},
	123: {},
	443: {},
}

var telemetrySafePorts = map[uint16]struct{}{
	80:   {},
	443:  {},
	8080: {},
	8443: {},
}

var wsl2SystemProcesses = map[string]struct{}{
	"init":       {},
	"systemd":    {},
	"wslhost":    {},
	"wsl":        {},
	"wslservice": {},
	"snapd":      {},
	"dockerd":    {},
	"containerd": {},
	"node":       {},
	"npm":        {},
	"npx":        {},
}

var telemetryParents = map[string]struct{}{
	"node":    {},
	"code":    {},
	"chrome":  {},
	"firefox": {},
}

var scriptChildExecutables = map[string]struct{}{
	"ps":       {},
	"ls":       {},
	"id":       {},
	"whoami":   {},
	"uname":    {},
	"cat":      {},
	"grep":     {},
	"awk":      {},
	"sed":      {},
	"find":     {},
	"which":    {},
	"hostname": {},
}

var neverSuppressProcessNames = map[string]struct{}{
	"bash":    {},
	"sh":      {},
	"python3": {},
	"python":  {},
	"nc":      {},
	"netcat":  {},
	"ncat":    {},
	"dash":    {},
}

var (
	defaultCIDROnce sync.Once
	defaultCIDRNets []*net.IPNet
)

func isDefaultWhitelistedProcessName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, item := range defaultProcessWhitelist {
		if n == item {
			return true
		}
	}
	return false
}

func isDefaultWhitelistedPath(exePath string) bool {
	clean := strings.ToLower(strings.TrimSpace(exePath))
	if clean == "" {
		return false
	}
	for _, marker := range defaultPathWhitelistContains {
		if strings.Contains(clean, marker) {
			return true
		}
	}
	return false
}

func isDefaultWhitelistedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	defaultCIDROnce.Do(func() {
		defaultCIDRNets = make([]*net.IPNet, 0, len(defaultIgnoredCIDRs))
		for _, cidr := range defaultIgnoredCIDRs {
			_, n, err := net.ParseCIDR(cidr)
			if err == nil && n != nil {
				defaultCIDRNets = append(defaultCIDRNets, n)
			}
		}
	})

	normalized := ip
	if v4 := ip.To4(); v4 != nil {
		normalized = v4
	}
	for _, n := range defaultCIDRNets {
		if n.Contains(normalized) {
			return true
		}
	}
	return false
}

func isDefaultSafePort(port uint16) bool {
	_, ok := defaultSafePorts[port]
	return ok
}

func processNameFromSession(s *correlation.SessionState) string {
	if s == nil {
		return ""
	}
	if len(s.ProcessTree) > 0 {
		name := strings.TrimSpace(s.ProcessTree[len(s.ProcessTree)-1].Comm)
		if name != "" {
			return name
		}
	}
	if s.ExePath != "" {
		return filepath.Base(strings.TrimSpace(s.ExePath))
	}
	return ""
}

func isNeverSuppressProcess(name string) bool {
	_, ok := neverSuppressProcessNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func isNeverSuppressSession(s *correlation.SessionState) bool {
	if s == nil {
		return false
	}

	if isNeverSuppressProcess(processNameFromSession(s)) {
		return true
	}

	if isNeverSuppressProcess(filepath.Base(strings.TrimSpace(s.ExePath))) {
		return true
	}

	for _, n := range s.ProcessTree {
		if isNeverSuppressProcess(n.Comm) {
			return true
		}
	}

	cmdline := strings.ToLower(strings.TrimSpace(s.Cmdline))
	for candidate := range neverSuppressProcessNames {
		if strings.Contains(cmdline, candidate) {
			return true
		}
	}

	return false
}

func shouldSuppressNode443Telemetry(s *correlation.SessionState) bool {
	if s == nil {
		return false
	}
	if s.RemotePort != 443 {
		return false
	}

	comm := ""
	if len(s.ProcessTree) > 0 {
		comm = strings.ToLower(strings.TrimSpace(s.ProcessTree[len(s.ProcessTree)-1].Comm))
	}

	exe := strings.ToLower(filepath.Base(strings.TrimSpace(s.ExePath)))
	cmdline := strings.ToLower(s.Cmdline)
	if comm == "node" || exe == "node" || strings.Contains(cmdline, "node") {
		return true
	}
	if comm == "code" || exe == "code" || strings.Contains(cmdline, "code") {
		return true
	}

	if strings.Contains(comm, "node") {
		return true
	}
	if strings.Contains(comm, "code") {
		return true
	}

	for _, n := range s.ProcessTree {
		p := strings.ToLower(strings.TrimSpace(n.Comm))
		if p == "node" || p == "code" || strings.Contains(p, "node") || strings.Contains(p, "code") {
			return true
		}
	}

	return false
}

func parentCommFromSession(s *correlation.SessionState) string {
	if s == nil || len(s.ProcessTree) < 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s.ProcessTree[len(s.ProcessTree)-2].Comm))
}

func shouldSuppressWSL2SystemProcess(s *correlation.SessionState) bool {
	comm := strings.ToLower(strings.TrimSpace(processNameFromSession(s)))
	_, ok := wsl2SystemProcesses[comm]
	return ok
}

func shouldSuppressSafePortTelemetry(s *correlation.SessionState) bool {
	if s == nil {
		return false
	}
	if _, ok := telemetrySafePorts[s.RemotePort]; !ok {
		return false
	}
	_, ok := telemetryParents[parentCommFromSession(s)]
	return ok
}

func shouldSuppressScriptChild(s *correlation.SessionState) bool {
	if s == nil {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(s.ExePath)))
	_, ok := scriptChildExecutables[base]
	return ok
}

func shouldSuppressDockerHealthCheck(s *correlation.SessionState) bool {
	if s == nil {
		return false
	}
	cmd := strings.ToLower(strings.TrimSpace(s.Cmdline))
	if strings.Contains(cmd, "healthcheck") {
		return true
	}
	return parentCommFromSession(s) == "dockerd"
}
