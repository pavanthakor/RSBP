package correlation

import "strings"

type Pattern struct {
	Name        string
	Description string
	Confidence  float64
	Match       func(*SessionState) bool
}

var KnownPatterns = []Pattern{
	{
		Name:        "DirectDup2Shell",
		Description: "execve(shell)+socket+connect+dup2/dup3 to stdio",
		Confidence:  0.95,
		Match: func(s *SessionState) bool {
			return s != nil && s.HasExecve && s.HasSocket && s.HasConnect && s.HasDupToStdio && IsShellBinary(s.ExePath)
		},
	},
	{
		Name:        "DevTCPBash",
		Description: "bash -i using /dev/tcp IP/port redirection",
		Confidence:  0.98,
		Match: func(s *SessionState) bool {
			if s == nil {
				return false
			}
			cmd := strings.ToLower(s.Cmdline)
			return strings.Contains(strings.ToLower(s.ExePath), "bash") && strings.Contains(cmd, "-i") && strings.Contains(cmd, "/dev/tcp/")
		},
	},
	{
		Name:        "SocatRelay",
		Description: "socat execution with outbound connect chain",
		Confidence:  0.92,
		Match: func(s *SessionState) bool {
			return s != nil && strings.Contains(strings.ToLower(s.ExePath), "socat") && s.HasSocket && s.HasConnect
		},
	},
	{
		Name:        "PythonSocket",
		Description: "python socket shell with stdio duplication",
		Confidence:  0.91,
		Match: func(s *SessionState) bool {
			if s == nil {
				return false
			}
			exe := strings.ToLower(s.ExePath)
			return (strings.Contains(exe, "python") || strings.Contains(strings.ToLower(s.Cmdline), "python")) && s.HasSocket && s.HasConnect && s.HasDupToStdio
		},
	},
	{
		Name:        "NcTraditional",
		Description: "nc/ncat reverse connect flow without mandatory dup2",
		Confidence:  0.88,
		Match: func(s *SessionState) bool {
			if s == nil {
				return false
			}
			exe := strings.ToLower(s.ExePath)
			return (strings.Contains(exe, "nc") || strings.Contains(exe, "ncat") || strings.Contains(exe, "netcat")) && s.HasConnect
		},
	},
	{
		Name:        "ForkPipeShell",
		Description: "fork/clone with pipe and dup to stdio before shell exec",
		Confidence:  0.90,
		Match: func(s *SessionState) bool {
			return s != nil && s.CategoryDetect() == 2 && s.HasForkWithPipe && s.HasDupToStdio && s.HasExecve
		},
	},
	{
		Name:        "XtermDisplay",
		Description: "xterm -display outbound callback pattern",
		Confidence:  0.80,
		Match: func(s *SessionState) bool {
			if s == nil {
				return false
			}
			cmd := strings.ToLower(s.Cmdline)
			return strings.Contains(cmd, "xterm") && strings.Contains(cmd, "-display")
		},
	},
	{
		Name:        "RubyExec",
		Description: "ruby -rsocket based reverse shell",
		Confidence:  0.87,
		Match: func(s *SessionState) bool {
			if s == nil {
				return false
			}
			cmd := strings.ToLower(s.Cmdline)
			return strings.Contains(strings.ToLower(s.ExePath), "ruby") && strings.Contains(cmd, "-rsocket")
		},
	},
}

func BestMatchPattern(s *SessionState) *Pattern {
	var best *Pattern
	for i := range KnownPatterns {
		p := &KnownPatterns[i]
		if p.Match == nil || !p.Match(s) {
			continue
		}
		if best == nil || p.Confidence > best.Confidence {
			best = p
		}
	}
	return best
}
