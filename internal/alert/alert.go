package alert

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/detection"
	"github.com/yoursec/rsbp/internal/enrichment"
	"github.com/yoursec/rsbp/internal/types"
)

type MITRETechnique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	URL    string `json:"url"`
}

type ProcessNode struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	ExePath   string    `json:"exe_path"`
	StartTime time.Time `json:"start_time"`
}

type ProcessDetails struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	ExePath   string    `json:"exe_path"`
	Cmdline   string    `json:"cmdline"`
	Comm      string    `json:"comm"`
	StartTime time.Time `json:"start_time"`
}

type NetworkDetails struct {
	RemoteIP         string   `json:"remote_ip"`
	RemotePort       string   `json:"remote_port"`
	Protocol         string   `json:"protocol"`
	ASN              uint32   `json:"asn"`
	ASNOrg           string   `json:"asn_org"`
	Country          string   `json:"country"`
	City             string   `json:"city"`
	IsVPN            bool     `json:"is_vpn"`
	IsTor            bool     `json:"is_tor"`
	ReputationScore  int      `json:"reputation_score"`
	ThreatCategories []string `json:"threat_categories"`
}

type HostInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	KernelVersion string `json:"kernel_version"`
	AgentVersion  string `json:"agent_version"`
}

type ScoreBreakdown struct {
	Rule   string  `json:"rule"`
	Score  float64 `json:"score"`
	Fired  bool    `json:"fired"`
	Reason string  `json:"reason"`
}

type ReverseShellAlert struct {
	ID                  string              `json:"id"`
	Timestamp           time.Time           `json:"timestamp"`
	Severity            types.AlertSeverity `json:"severity"`
	Score               float64             `json:"score"`
	ShellCategory       int                 `json:"shell_category"`
	CategoryDescription string              `json:"category_description"`
	Pattern             string              `json:"pattern"`
	Process             ProcessDetails      `json:"process"`
	ProcessTree         []ProcessNode       `json:"process_tree"`
	Network             NetworkDetails      `json:"network"`
	SyscallChain        []string            `json:"syscall_chain"`
	MITRETechniques     []MITRETechnique    `json:"mitre_techniques"`
	FiredRules          []string            `json:"fired_rules"`
	ScoreBreakdown      []ScoreBreakdown    `json:"score_breakdown"`
	ForensicBundlePath  string              `json:"forensic_bundle_path"`
	Suppressed          bool                `json:"suppressed"`
	SuppressReason      string              `json:"suppress_reason"`
	HostInfo            HostInfo            `json:"host_info"`
	PipelineStart       time.Time           `json:"-"`
}

type DetectionResult = detection.DetectionResult

type Builder struct {
	hostname     string
	agentVersion string
	osName       string
	kernel       string
}

func NewBuilder(hostname, agentVersion string) *Builder {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &Builder{
		hostname:     hostname,
		agentVersion: agentVersion,
		osName:       runtime.GOOS,
		kernel:       kernelVersion(),
	}
}

func (b *Builder) Build(session *correlation.SessionState, detection *DetectionResult, enr *enrichment.Result) *ReverseShellAlert {
	if session == nil {
		return nil
	}

	det := normalizeDetection(detection)
	res := normalizeEnrichment(enr)
	pattern := ""
	if len(det.FiredRules) > 0 {
		pattern = strings.TrimSpace(det.FiredRules[0])
	}
	if pattern == "" {
		if p := correlation.BestMatchPattern(session); p != nil {
			pattern = p.Name
		}
	}

	out := &ReverseShellAlert{
		ID:                  newUUIDv4(),
		Timestamp:           time.Now().UTC(),
		Severity:            det.Severity,
		Score:               det.Score,
		ShellCategory:       session.CategoryDetect(),
		CategoryDescription: describeCategory(session.CategoryDetect()),
		Pattern:             pattern,
		Process: ProcessDetails{
			PID:       session.PID,
			PPID:      session.PPID,
			UID:       session.UID,
			GID:       session.GID,
			ExePath:   session.ExePath,
			Cmdline:   session.Cmdline,
			Comm:      processComm(session),
			StartTime: session.StartTime,
		},
		ProcessTree: mapProcessTree(session.ProcessTree),
		Network: NetworkDetails{
			RemoteIP:         ipToString(session.RemoteIP),
			RemotePort:       strconv.Itoa(int(session.RemotePort)),
			Protocol:         "tcp",
			ASN:              res.ASN,
			ASNOrg:           res.ASNOrg,
			Country:          res.Country,
			City:             res.City,
			IsVPN:            res.IsVPN,
			IsTor:            res.IsTor,
			ReputationScore:  res.ReputationScore,
			ThreatCategories: append([]string(nil), res.ThreatCategories...),
		},
		SyscallChain:       formatSyscallChain(session),
		MITRETechniques:    mitreForSession(session),
		FiredRules:         append([]string(nil), det.FiredRules...),
		ScoreBreakdown:     buildScoreBreakdown(det.FiredRules, session),
		ForensicBundlePath: "",
		Suppressed:         det.Suppressed,
		SuppressReason:     det.SuppressReason,
		HostInfo: HostInfo{
			Hostname:      b.hostname,
			OS:            b.osName,
			KernelVersion: b.kernel,
			AgentVersion:  b.agentVersion,
		},
	}

	return out
}

func buildScoreBreakdown(firedRules []string, session *correlation.SessionState) []ScoreBreakdown {
	out := make([]ScoreBreakdown, 0, len(firedRules))
	for _, ruleID := range firedRules {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			continue
		}
		out = append(out, ScoreBreakdown{
			Rule:   ruleID,
			Score:  detection.RuleScore(ruleID),
			Fired:  true,
			Reason: detection.RuleReason(ruleID, session),
		})
	}
	return out
}

func normalizeDetection(d *DetectionResult) *DetectionResult {
	if d == nil {
		return &DetectionResult{
			Severity: types.SeverityMedium,
			Score:    0.75,
			FiredRules: []string{
				"LowFPCombinedRule",
			},
		}
	}
	out := *d
	if out.Severity == "" {
		out.Severity = types.SeverityMedium
	}
	if out.Score <= 0 {
		out.Score = 0.75
	}
	return &out
}

func normalizeEnrichment(e *enrichment.Result) *enrichment.Result {
	if e == nil {
		return &enrichment.Result{}
	}
	return e
}

func newUUIDv4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
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

func describeCategory(category int) string {
	switch category {
	case 1:
		return "Direct shell with stdio duplication"
	case 2:
		return "Fork and pipe mediated reverse shell"
	case 3:
		return "IPC-assisted reverse shell"
	default:
		return "Unknown or incomplete shell pattern"
	}
}

func processComm(s *correlation.SessionState) string {
	if s == nil {
		return ""
	}
	if len(s.ProcessTree) > 0 {
		return s.ProcessTree[len(s.ProcessTree)-1].Comm
	}
	parts := strings.Split(strings.TrimSpace(s.ExePath), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func mapProcessTree(in []correlation.ProcessNode) []ProcessNode {
	out := make([]ProcessNode, 0, len(in))
	for _, n := range in {
		out = append(out, ProcessNode{
			PID:       n.PID,
			PPID:      n.PPID,
			Comm:      n.Comm,
			ExePath:   n.ExePath,
			StartTime: n.StartTime,
		})
	}
	return out
}

func formatSyscallChain(s *correlation.SessionState) []string {
	if s == nil {
		return nil
	}
	chain := make([]string, 0, 8)
	if s.HasExecve {
		chain = append(chain, "execve")
	}
	if s.HasSocket {
		chain = append(chain, "socket")
	}
	if s.HasConnect {
		chain = append(chain, "connect")
	}
	if s.HasDupToStdio {
		chain = append(chain, "dup2(0)", "dup2(1)", "dup2(2)")
	}
	if s.HasForkWithPipe {
		chain = append(chain, "fork", "pipe")
	}
	return chain
}

func mitreForSession(s *correlation.SessionState) []MITRETechnique {
	out := []MITRETechnique{
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", URL: "https://attack.mitre.org/techniques/T1059/"},
	}
	if s != nil && (s.HasConnect || s.HasSocket) {
		out = append(out,
			MITRETechnique{ID: "T1104", Name: "Multi-Stage Channels", Tactic: "Command and Control", URL: "https://attack.mitre.org/techniques/T1104/"},
		)
	}
	if s != nil && s.HasDupToStdio {
		out = append(out,
			MITRETechnique{ID: "T1571", Name: "Non-Standard Port", Tactic: "Command and Control", URL: "https://attack.mitre.org/techniques/T1571/"},
		)
	}
	return out
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func kernelVersion() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
