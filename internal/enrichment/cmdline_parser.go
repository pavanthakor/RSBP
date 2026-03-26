package enrichment

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	devTCPRegex = regexp.MustCompile(`(?:bash|sh).*-[ic].*>&\s*/dev/tcp/([^/]+)/(\d+)`)
	socatRegex  = regexp.MustCompile(`socat\s+(?:TCP|TCP4|TCP6):\s*([^:]+):(\d+)`)
	pythonRegex = regexp.MustCompile(`connect\(['\"]([^'\"]+)['\"]\s*,\s*(\d+)\)`)
	ncRegex     = regexp.MustCompile(`nc\s+(?:-[evn]+\s+)?([^\s]+)\s+(\d+)`)
)

func ParseCmdlineForC2(cmdline string) (ip string, port int, technique string, ok bool) {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return "", 0, "", false
	}

	if m := devTCPRegex.FindStringSubmatch(cmdline); len(m) == 3 {
		p, err := strconv.Atoi(m[2])
		if err == nil {
			return m[1], p, "dev_tcp_bash", true
		}
	}

	if m := socatRegex.FindStringSubmatch(cmdline); len(m) == 3 {
		p, err := strconv.Atoi(m[2])
		if err == nil {
			return m[1], p, "socat", true
		}
	}

	if m := pythonRegex.FindStringSubmatch(cmdline); len(m) == 3 {
		p, err := strconv.Atoi(m[2])
		if err == nil {
			return m[1], p, "python_socket", true
		}
	}

	if m := ncRegex.FindStringSubmatch(cmdline); len(m) == 3 {
		p, err := strconv.Atoi(m[2])
		if err == nil {
			return m[1], p, "netcat", true
		}
	}

	return "", 0, "", false
}
