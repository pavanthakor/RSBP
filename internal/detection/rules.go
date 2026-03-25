package detection

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/enrichment"
	"github.com/yoursec/rsbp/internal/types"
)

type RuleInput struct {
	Session     *correlation.SessionState
	Enrichment  *enrichment.Result
	Whitelisted bool
	EventTime   time.Time
}

type RuleEvaluation struct {
	FiredRules     []string
	Suppressed     bool
	SuppressReason string
	Score          float64
	Severity       types.AlertSeverity
}

type DetectionResult = RuleEvaluation

type Rule interface {
	ID() string
	Name() string
	Evaluate(in RuleInput) bool
}

type weightedRule struct {
	id       string
	name     string
	score    float64
	evaluate func(in RuleInput) bool
}

func (r weightedRule) ID() string { return r.id }

func (r weightedRule) Name() string { return r.name }

func (r weightedRule) Evaluate(in RuleInput) bool {
	if r.evaluate == nil {
		return false
	}
	return r.evaluate(in)
}

var (
	highRiskIPRule = weightedRule{
		id:    "HighRiskIPRule",
		name:  "High Risk IP Reputation",
		score: 0.30,
		evaluate: func(in RuleInput) bool {
			if in.Enrichment == nil {
				return false
			}
			return in.Enrichment.ReputationScore >= 85 || in.Enrichment.AbuseConfidenceScore >= 80
		},
	}

	suspiciousCommandRule = weightedRule{
		id:    "SuspiciousCommandRule",
		name:  "Suspicious Reverse Shell Command",
		score: 0.25,
		evaluate: func(in RuleInput) bool {
			if in.Session == nil {
				return false
			}
			cmd := strings.ToLower(in.Session.Cmdline)
			exe := strings.ToLower(in.Session.ExePath)
			return strings.Contains(cmd, "/dev/tcp/") ||
				(strings.Contains(cmd, "python") && strings.Contains(cmd, "socket")) ||
				strings.Contains(exe, "nc") ||
				strings.Contains(exe, "socat")
		},
	}

	correlatedBehaviorRule = weightedRule{
		id:    "CorrelatedBehaviorRule",
		name:  "Correlated Syscall Behavior",
		score: 0.35,
		evaluate: func(in RuleInput) bool {
			if in.Session == nil {
				return false
			}
			if !(in.Session.HasSocket || in.Session.HasDupToStdio || in.Session.HasForkWithPipe) {
				return false
			}
			return in.Session.CategoryDetect() > 0 && in.Session.IsComplete()
		},
	}

	lowFPCombinedRule = weightedRule{
		id:    "LowFPCombinedRule",
		name:  "Low False Positive Combined Rule",
		score: 0.50,
		evaluate: func(in RuleInput) bool {
			if in.Session == nil {
				return false
			}
			count := 0
			if in.Session.HasDupToStdio {
				count++
			}
			if IsExternalIP(in.Session.RemoteIP) {
				count++
			}
			if IsInteractiveShell(in.Session) {
				count++
			}
			return count >= 2
		},
	}

	interactiveShellRule = weightedRule{
		id:    "InteractiveShellRule",
		name:  "Interactive Shell Behavior",
		score: 0.40,
		evaluate: func(in RuleInput) bool {
			return IsInteractiveShell(in.Session)
		},
	}

	externalIPRule = weightedRule{
		id:    "ExternalIPRule",
		name:  "External Remote IP",
		score: 0.30,
		evaluate: func(in RuleInput) bool {
			if in.Session == nil {
				return false
			}
			return IsExternalIP(in.Session.RemoteIP)
		},
	}

	ephemeralPortRule = weightedRule{
		id:    "EphemeralPortRule",
		name:  "Ephemeral Remote Port",
		score: 0.15,
		evaluate: func(in RuleInput) bool {
			if in.Session == nil {
				return false
			}
			return in.Session.RemotePort >= 40000
		},
	}

	c2PortRule = weightedRule{
		id:    "C2PortRule",
		name:  "Classic C2 Port",
		score: 0.25,
		evaluate: func(in RuleInput) bool {
			if in.Session == nil {
				return false
			}
			switch in.Session.RemotePort {
			case 4444, 4445, 1234, 31337, 6666, 9001, 8888, 6969:
				return true
			default:
				return false
			}
		},
	}

	unusualTimeRule = weightedRule{
		id:    "UnusualTimeRule",
		name:  "Unusual UTC Activity Window",
		score: 0.10,
		evaluate: func(in RuleInput) bool {
			t := in.EventTime
			if t.IsZero() {
				t = time.Now().UTC()
			}
			h := t.UTC().Hour()
			return h >= 2 && h <= 5
		},
	}

	threatIntelRule = weightedRule{
		id:    "ThreatIntelRule",
		name:  "Threat Intelligence Reputation",
		score: 0.30,
		evaluate: func(in RuleInput) bool {
			if in.Enrichment == nil {
				return false
			}
			return in.Enrichment.ReputationScore > 80
		},
	}
)

func DefaultRules() []Rule {
	return []Rule{
		externalIPRule,
		c2PortRule,
		suspiciousCommandRule,
		correlatedBehaviorRule,
		lowFPCombinedRule,
		ephemeralPortRule,
		unusualTimeRule,
		threatIntelRule,
	}
}

func ruleScore(ruleID string) float64 {
	switch ruleID {
	case "InteractiveShellRule":
		return 0.40
	case "ExternalIPRule":
		return 0.30
	case "C2PortRule":
		return 0.25
	case "HighRiskIPRule":
		return 0.30
	case "SuspiciousCommandRule":
		return 0.25
	case "CorrelatedBehaviorRule":
		return 0.35
	case "LowFPCombinedRule":
		return 0.50
	case "EphemeralPortRule":
		return 0.15
	case "UnusualTimeRule":
		return 0.10
	case "ThreatIntelRule":
		return 0.30
	default:
		return 0
	}
}

func RuleScore(ruleID string) float64 {
	return ruleScore(ruleID)
}

func IsExternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	normalized := ip.To16()
	if normalized == nil {
		return false
	}
	if normalized.IsLoopback() || normalized.IsUnspecified() || normalized.IsPrivate() || normalized.IsLinkLocalUnicast() {
		return false
	}
	if v4 := normalized.To4(); v4 != nil {
		if v4[0] == 10 {
			return false
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return false
		}
		if v4[0] == 192 && v4[1] == 168 {
			return false
		}
		if v4[0] == 127 {
			return false
		}
		if v4[0] == 169 && v4[1] == 254 {
			return false
		}
	}
	return true
}

func IsInteractiveShell(s *correlation.SessionState) bool {
	if s == nil {
		return false
	}
	comm := strings.ToLower(strings.TrimSpace(processNameFromSession(s)))
	if _, ok := correlation.ShellBinaries[comm]; !ok {
		return false
	}
	exeBase := strings.ToLower(filepath.Base(strings.TrimSpace(s.ExePath)))
	if _, ok := correlation.ShellBinaries[exeBase]; !ok {
		return false
	}
	if ext := strings.ToLower(filepath.Ext(exeBase)); ext != "" {
		return false
	}
	cmd := strings.ToLower(strings.TrimSpace(s.Cmdline))
	return strings.Contains(cmd, " -i") || strings.Contains(cmd, " -c") || strings.Contains(cmd, "/dev/tcp")
}

func RuleReason(ruleID string, s *correlation.SessionState) string {
	switch ruleID {
	case "LowFPCombinedRule":
		indicators := make([]string, 0, 3)
		if s != nil && s.HasDupToStdio {
			indicators = append(indicators, "dup2 stdio")
		}
		if s != nil && IsExternalIP(s.RemoteIP) {
			indicators = append(indicators, "external IP")
		}
		if IsInteractiveShell(s) {
			indicators = append(indicators, "interactive shell")
		}
		if len(indicators) == 0 {
			return "at least two low-FP indicators matched"
		}
		return fmt.Sprintf("low-FP indicators matched: %s", strings.Join(indicators, "+"))
	case "ExternalIPRule":
		if s != nil && s.RemoteIP != nil {
			return fmt.Sprintf("remote IP %s is not RFC1918/loopback/link-local", s.RemoteIP.String())
		}
		return "remote IP is external"
	case "C2PortRule":
		if s != nil {
			return fmt.Sprintf("port %d is known C2 port", s.RemotePort)
		}
		return "known C2 port detected"
	case "InteractiveShellRule":
		return "interactive shell flags or /dev/tcp behavior detected"
	case "CorrelatedBehaviorRule":
		return "execve+socket/connect behavior correlated"
	case "SuspiciousCommandRule":
		return "command line contains reverse-shell traits"
	case "HighRiskIPRule":
		return "IP reputation or abuse confidence is high"
	case "EphemeralPortRule":
		return "remote port is ephemeral/high-numbered"
	case "UnusualTimeRule":
		return "activity occurred in unusual UTC window"
	case "ThreatIntelRule":
		return "threat-intel score indicates elevated risk"
	default:
		return "rule matched"
	}
}

func EvaluateRules(in RuleInput) RuleEvaluation {
	return EvaluateRulesWithRules(in, DefaultRules())
}

func EvaluateRulesWithRules(in RuleInput, rules []Rule) RuleEvaluation {
	if in.Whitelisted {
		return RuleEvaluation{
			Suppressed:     true,
			SuppressReason: "whitelisted",
			Score:          0,
			Severity:       types.SeverityLow,
		}
	}

	fired := make([]string, 0, len(rules))
	score := 0.0

	for _, rule := range rules {
		if rule == nil || !rule.Evaluate(in) {
			continue
		}
		fired = append(fired, rule.ID())
		score += ruleScore(rule.ID())
	}

	if score > 1 {
		score = 1
	}

	return RuleEvaluation{
		FiredRules: fired,
		Score:      score,
		Severity:   scoreToSeverity(score),
	}
}
