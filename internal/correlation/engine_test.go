package correlation

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/types"
)

func TestEngineEmitsCompleteSessionOncePerKey(t *testing.T) {
	SetAllowPrivateRemote(true)
	out := make(chan *SessionState, 8)
	eng := New(5*time.Second, out, zap.NewNop())

	events := []types.SyscallEvent{
		mkEvent(1001, 59, "/bin/bash", "bash -i", 0, "", 0),
		mkEvent(1001, 42, "/bin/bash", "", 3, "1.2.3.4", 4444),
		mkDupEvent(1001),
		mkDupEvent(1001),
	}
	for _, ev := range events {
		eng.Process(ev)
	}

	emitted := 0
	drain(out, &emitted)
	if emitted != 1 {
		t.Fatalf("expected single emission, got %d", emitted)
	}

	eng.Process(mkDupEvent(1001))
	drain(out, &emitted)
	if emitted != 1 {
		t.Fatalf("expected dedupe to suppress repeat emit, got %d", emitted)
	}
}

func TestEngineAllowsSecondEmitForDifferentRemoteIP(t *testing.T) {
	SetAllowPrivateRemote(true)
	out := make(chan *SessionState, 8)
	eng := New(5*time.Second, out, zap.NewNop())

	for _, ev := range []types.SyscallEvent{
		mkEvent(2001, 59, "/bin/bash", "bash -i", 0, "", 0),
		mkEvent(2001, 42, "/bin/bash", "", 3, "1.2.3.4", 4444),
		mkDupEvent(2001),
	} {
		eng.Process(ev)
	}

	emitted := 0
	drain(out, &emitted)
	if emitted != 1 {
		t.Fatalf("expected first emission, got %d", emitted)
	}

	for _, ev := range []types.SyscallEvent{
		mkEvent(2001, 42, "/bin/bash", "", 3, "5.6.7.8", 5555),
		mkDupEvent(2001),
	} {
		eng.Process(ev)
	}
	drain(out, &emitted)
	if emitted != 2 {
		t.Fatalf("expected second emission for new remote ip, got %d", emitted)
	}
}

func TestPrivateRemoteFilterConfigurable(t *testing.T) {
	SetAllowPrivateRemote(false)
	defer SetAllowPrivateRemote(true)

	s := &SessionState{
		PID:           3001,
		ExePath:       "/bin/bash",
		HasExecve:     true,
		HasConnect:    true,
		HasDupToStdio: true,
		RemoteIP:      net.ParseIP("192.168.1.10"),
		RemotePort:    4444,
	}
	if s.IsComplete() {
		t.Fatalf("expected private remote to be blocked when filter disabled")
	}

	SetAllowPrivateRemote(true)
	if !s.IsComplete() {
		t.Fatalf("expected private remote to be allowed when filter enabled")
	}

	SetAllowPrivateRemote(false)
	public := &SessionState{
		PID:           3002,
		ExePath:       "/bin/bash",
		HasExecve:     true,
		HasConnect:    true,
		HasDupToStdio: true,
		RemoteIP:      net.ParseIP("8.8.8.8"),
		RemotePort:    4444,
	}
	if !public.IsComplete() {
		t.Fatalf("expected public remote to remain allowed when private filter disabled")
	}
}

func mkDupEvent(pid uint32) types.SyscallEvent {
	ev := mkEvent(pid, 33, "/bin/bash", "", 3, "", 0)
	ev.HasDup2Stdio = 1
	return ev
}

func mkEvent(pid uint32, syscall uint32, exe string, args string, fd int32, ip string, port uint16) types.SyscallEvent {
	ev := types.SyscallEvent{
		PID:         pid,
		PPID:        1,
		UID:         1000,
		GID:         1000,
		SyscallNr:   syscall,
		FD:          fd,
		TimestampNS: uint64(time.Now().UnixNano()),
		Family:      2,
	}
	copy(ev.ExecPath[:], []byte(exe))
	copy(ev.Args[:], []byte(args))
	copy(ev.Comm[:], []byte("bash"))
	if ip != "" {
		v4 := net.ParseIP(ip).To4()
		if v4 != nil {
			ev.RemoteIP4 = uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
			ev.RemotePort = port
		}
	}
	return ev
}

func drain(ch <-chan *SessionState, count *int) {
	for {
		select {
		case <-ch:
			*count = *count + 1
		default:
			return
		}
	}
}
