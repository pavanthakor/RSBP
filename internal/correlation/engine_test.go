package correlation

import (
	"net"
	"path/filepath"
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
		mkEvent(1001, 59, "/bin/xyz", "xyz -i", 0, "", 0),
		mkEvent(1001, 42, "/bin/xyz", "", 3, "1.2.3.4", 4444),
		mkDupEventXYZ(1001),
		mkDupEventXYZ(1001),
	}
	for _, ev := range events {
		eng.Process(ev)
	}

	emitted := 0
	for {
		select {
		case session := <-out:
			emitted++
			t.Logf("Emitted: PID=%d Category=%d HasDup=%v Cmd=%s Exe=%s Name=%s", session.PID, session.CategoryDetect(), session.HasDupToStdio, session.Cmdline, session.ExePath, session.ProcessName())
		default:
			goto done
		}
	}
done:
	if emitted != 1 {
		t.Fatalf("expected single emission, got %d", emitted)
	}

	eng.Process(mkDupEventXYZ(1001))
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
		mkEvent(2001, 59, "/bin/xyz", "xyz -i", 0, "", 0),
		mkEvent(2001, 42, "/bin/xyz", "", 3, "1.2.3.4", 4444),
		mkDupEventXYZ(2001),
	} {
		eng.Process(ev)
	}

	emitted := 0
	for {
		select {
		case <-out:
			emitted++
		default:
			goto done2
		}
	}
done2:
	if emitted != 1 {
		t.Fatalf("expected first emission, got %d", emitted)
	}

	for _, ev := range []types.SyscallEvent{
		mkEvent(2001, 42, "/bin/xyz", "", 3, "5.6.7.8", 5555),
		mkDupEventXYZ(2001),
	} {
		eng.Process(ev)
	}
	for {
		select {
		case <-out:
			emitted++
		default:
			goto done3
		}
	}
done3:
	if emitted != 2 {
		t.Fatalf("expected second emission for new remote ip, got %d", emitted)
	}
}

func TestPrivateRemoteFilterConfigurable(t *testing.T) {
	// IP filtering moved to detection engine. Correlation handles behavior only.
	s := &SessionState{
		PID:        3001,
		ExePath:    "/bin/bash",
		HasExecve:  true,
		HasConnect: true,
		HasSocket:  true,
		RemoteIP:   net.ParseIP("192.168.1.10"),
		RemotePort: 4444,
	}
	if !s.IsComplete() {
		t.Fatalf("expected private remote to be complete in correlation layer")
	}

	s.HasDupToStdio = true
	if !s.IsComplete() {
		t.Fatalf("expected private remote to be allowed when strong behavior (dup2)")
	}
}

func mkDupEventXYZ(pid uint32) types.SyscallEvent {
	ev := mkEvent(pid, 33, "/bin/xyz", "", 3, "", 0)
	ev.HasDup2Stdio = 1
	return ev
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

	base := filepath.Base(exe)
	copy(ev.Comm[:], []byte(base))

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
