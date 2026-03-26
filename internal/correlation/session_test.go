package correlation

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/types"
)

func TestHelpersAndPatternSelection(t *testing.T) {
	if !IsShellBinary("/bin/bash") {
		t.Fatalf("expected bash to be recognized as shell binary")
	}
	if IsShellBinary("/usr/bin/code") {
		t.Fatalf("did not expect code to be recognized as shell binary")
	}

	state := &SessionState{
		ExePath:       "/usr/bin/python3",
		Cmdline:       "python3 -c import socket",
		HasExecve:     true,
		HasSocket:     true,
		HasConnect:    true,
		HasDupToStdio: true,
		RemoteIP:      net.ParseIP("8.8.8.8"),
		RemotePort:    4444,
	}
	if best := BestMatchPattern(state); best == nil || best.Name == "" {
		t.Fatalf("expected best pattern match")
	}

	if !isPublicRemoteIP(net.ParseIP("8.8.8.8")) {
		t.Fatalf("expected public IP to be accepted")
	}
	if isPublicRemoteIP(net.ParseIP("10.0.0.7")) {
		t.Fatalf("expected private IP to be rejected")
	}
}

func TestEngineRunCleanupAndDebugSnapshot(t *testing.T) {
	out := make(chan *SessionState, 8)
	eng := New(2*time.Second, out, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan types.SyscallEvent, 4)
	go eng.Run(ctx, in)

	ev := types.SyscallEvent{PID: 9001, PPID: 1, SyscallNr: 59, TimestampNS: uint64(time.Now().UnixNano())}
	copy(ev.ExecPath[:], []byte("/bin/bash"))
	in <- ev
	close(in)
	time.Sleep(20 * time.Millisecond)

	snap, ok := eng.DebugSnapshot(9001)
	if !ok || snap == "" {
		t.Fatalf("expected debug snapshot for pid=9001")
	}

	stale := &SessionState{
		PID:        9999,
		ExePath:    "/bin/bash",
		HasExecve:  true,
		StartTime:  time.Now().Add(-10 * time.Second),
		LastUpdate: time.Now().Add(-10 * time.Second),
	}
	eng.sessions.Store(uint32(9999), stale)
	eng.cleanup()
	if _, found := eng.sessions.Load(uint32(9999)); found {
		t.Fatalf("expected stale incomplete session to be cleaned up")
	}
}

func TestTrackerConsumeAndEngineNilSafety(t *testing.T) {
	var eng *Engine
	eng.Process(types.SyscallEvent{})
	eng.Run(context.Background(), nil)

	tracker := NewTracker(5 * time.Second)
	ev := types.SyscallEvent{
		PID:         7777,
		PPID:        1,
		SyscallNr:   59,
		TimestampNS: uint64(time.Now().UnixNano()),
	}
	copy(ev.ExecPath[:], []byte("/bin/bash"))
	copy(ev.Args[:], []byte("bash -i"))
	state := tracker.Consume(ev)
	if state == nil {
		t.Fatalf("expected tracker to return state")
	}
}

func TestLowLevelHelpers(t *testing.T) {
	now := timestampToTime(0)
	if now.IsZero() {
		t.Fatalf("timestampToTime(0) should return current time")
	}

	specific := timestampToTime(uint64(time.Unix(12, 34).UnixNano()))
	if specific.Unix() != 12 {
		t.Fatalf("expected unix seconds 12, got %d", specific.Unix())
	}

	v4 := uint32(1) | uint32(2)<<8 | uint32(3)<<16 | uint32(4)<<24
	if got := ipFromFields(2, v4, [16]byte{}).String(); got != "1.2.3.4" {
		t.Fatalf("unexpected ipv4 decode: %s", got)
	}

	var raw6 [16]byte
	raw6[0], raw6[15] = 0x20, 0x01
	if ipFromFields(10, 0, raw6) == nil {
		t.Fatalf("expected ipv6 decode")
	}

	if ipFromFields(10, 0, [16]byte{}) != nil {
		t.Fatalf("expected all-zero address to decode as nil")
	}

	var comm [16]byte
	copy(comm[:], []byte("bash\x00unused"))
	if got := commToString(comm); got != "bash" {
		t.Fatalf("unexpected comm string: %s", got)
	}
}

func TestSessionIsCompleteBehavior(t *testing.T) {
	// IsComplete should classify likely reverse-shell sessions as "complete" while
	// suppressing obvious noise from built-in whitelists.
	incomplete := &SessionState{
		PID:        9002,
		ExePath:    "/bin/bash",
		HasExecve:  true,
		HasConnect: false, // Incomplete
	}

	if incomplete.IsComplete() {
		t.Fatalf("expected incomplete without connect")
	}

	complete1 := &SessionState{
		PID:           9002,
		ExePath:       "/bin/bash",
		HasExecve:     true,
		HasConnect:    true,
		HasDupToStdio: true, // Complete via dup
		RemoteIP:      net.ParseIP("8.8.8.8"),
		RemotePort:    4444,
	}
	if !complete1.IsComplete() {
		t.Fatalf("expected complete with execve, connect, and dup")
	}

	complete2 := &SessionState{
		PID:        9002,
		ExePath:    "/bin/bash",
		HasExecve:  true,
		HasConnect: true,
		HasSocket:  true, // Complete via socket
		RemoteIP:   net.ParseIP("8.8.8.8"),
		RemotePort: 4444,
	}
	if !complete2.IsComplete() {
		t.Fatalf("expected complete with execve, connect, and socket")
	}

	// RS tools should be allowed to complete on private targets (common for simulation/labs).
	rsPrivateNoExec := &SessionState{
		ExePath:    "/bin/bash",
		HasExecve:  false,
		HasConnect: true,
		RemoteIP:   net.ParseIP("10.0.0.7"),
		RemotePort: 4444,
	}
	if !rsPrivateNoExec.IsComplete() {
		t.Fatalf("expected RS tool to complete on private target even without execve")
	}

	// RS tools should still be suppressed for true loopback/unspecified targets.
	rsLoopback := &SessionState{
		ExePath:    "/bin/bash",
		HasConnect: true,
		RemoteIP:   net.ParseIP("127.0.0.1"),
		RemotePort: 4444,
	}
	if rsLoopback.IsComplete() {
		t.Fatalf("expected RS tool loopback session to be suppressed")
	}

	// Non-RS processes in the built-in process whitelist should not complete.
	whitelistedProc := &SessionState{
		ExePath:    "/usr/bin/curl",
		HasExecve:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("8.8.8.8"),
		RemotePort: 4444,
	}
	if whitelistedProc.IsComplete() {
		t.Fatalf("expected built-in whitelisted process to be suppressed")
	}

	// Non-RS processes connecting to private IPs should not complete (noise suppression).
	privateNonTool := &SessionState{
		ExePath:    "/usr/bin/myproc",
		HasExecve:  true,
		HasConnect: true,
		RemoteIP:   net.ParseIP("192.168.1.20"),
		RemotePort: 4444,
	}
	if privateNonTool.IsComplete() {
		t.Fatalf("expected non-RS process to be suppressed on private targets")
	}
}

func TestCategoryDetectDirectPatterns(t *testing.T) {
	shell := &SessionState{
		ExePath:       "/bin/bash",
		HasExecve:     true,
		HasConnect:    true,
		HasDupToStdio: true,
	}
	if got := shell.CategoryDetect(); got != 1 {
		t.Fatalf("expected shell direct pattern category=1, got %d", got)
	}

	netcat := &SessionState{
		ExePath:    "/usr/bin/nc",
		HasExecve:  true,
		HasConnect: true,
	}
	if got := netcat.CategoryDetect(); got != 1 {
		t.Fatalf("expected netcat direct pattern category=1, got %d", got)
	}
}
