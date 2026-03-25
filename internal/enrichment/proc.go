package enrichment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

type ProcessInfo struct {
	PID       uint32            `json:"pid"`
	PPID      uint32            `json:"ppid"`
	Comm      string            `json:"comm"`
	ExePath   string            `json:"exe_path"`
	Cmdline   string            `json:"cmdline"`
	StartTime time.Time         `json:"start_time"`
	UID       uint32            `json:"uid"`
	GID       uint32            `json:"gid"`
	Cgroups   string            `json:"cgroups"`
	NSIDs     map[string]uint64 `json:"nsids"`
}

type FDInfo struct {
	FD          int    `json:"fd"`
	Type        string `json:"type"`
	Target      string `json:"target"`
	SocketInode uint64 `json:"socket_inode"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
}

type NetConn struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
	Inode      uint64 `json:"inode"`
}

type ProcBundle struct {
	ProcessTree        []ProcessInfo `json:"process_tree"`
	OpenFDs            []FDInfo      `json:"open_fds"`
	NetworkConnections []NetConn     `json:"network_connections"`
}

type ProcEnricher struct {
	procRoot string
	logger   *zap.Logger
}

var socketInodeRe = regexp.MustCompile(`^socket:\[(\d+)\]$`)

func NewProcEnricher(procRoot string, logger *zap.Logger) *ProcEnricher {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ProcEnricher{procRoot: procRoot, logger: logger}
}

func (p *ProcEnricher) Collect(pid uint32) (*ProcBundle, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	bundle := &ProcBundle{
		ProcessTree:        make([]ProcessInfo, 0, 6),
		OpenFDs:            make([]FDInfo, 0, 32),
		NetworkConnections: make([]NetConn, 0, 64),
	}

	connByInode := make(map[uint64]NetConn)
	for _, f := range []struct {
		name  string
		proto string
	}{
		{name: "tcp", proto: "tcp"},
		{name: "tcp6", proto: "tcp6"},
	} {
		rows, err := p.readProcNetTCP(ctx, f.name, f.proto, pid)
		if err != nil {
			continue
		}
		for _, row := range rows {
			connByInode[row.Inode] = row
			bundle.NetworkConnections = append(bundle.NetworkConnections, row)
		}
	}

	cur := pid
	for depth := 0; depth < 5 && cur != 0; depth++ {
		info, err := p.readProcessInfo(ctx, cur)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			break
		}
		bundle.ProcessTree = append(bundle.ProcessTree, *info)
		cur = info.PPID
	}

	fds, err := p.readFDs(ctx, pid, connByInode)
	if err == nil {
		bundle.OpenFDs = append(bundle.OpenFDs, fds...)
	}

	return bundle, nil
}

func (p *ProcEnricher) readProcessInfo(ctx context.Context, pid uint32) (*ProcessInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pidStr := strconv.FormatUint(uint64(pid), 10)
	procDir := filepath.Join(p.procRoot, pidStr)

	statusData, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return nil, err
	}

	ppid := uint32(0)
	uid := uint32(0)
	gid := uint32(0)
	comm := ""
	for _, line := range strings.Split(string(statusData), "\n") {
		if strings.HasPrefix(line, "Name:\t") {
			comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:\t"))
		}
		if strings.HasPrefix(line, "PPid:\t") {
			ppid = uint32(parseUint(strings.TrimSpace(strings.TrimPrefix(line, "PPid:\t"))))
		}
		if strings.HasPrefix(line, "Uid:\t") {
			parts := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
			if len(parts) > 0 {
				uid = uint32(parseUint(parts[0]))
			}
		}
		if strings.HasPrefix(line, "Gid:\t") {
			parts := strings.Fields(strings.TrimPrefix(line, "Gid:\t"))
			if len(parts) > 0 {
				gid = uint32(parseUint(parts[0]))
			}
		}
	}

	exePath, _ := os.Readlink(filepath.Join(procDir, "exe"))
	cmdlineRaw, _ := os.ReadFile(filepath.Join(procDir, "cmdline"))
	cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdlineRaw), "\x00", " "))
	cgroupsRaw, _ := os.ReadFile(filepath.Join(procDir, "cgroup"))
	cgroups := strings.TrimSpace(string(cgroupsRaw))

	nsids := map[string]uint64{}
	nsDir := filepath.Join(procDir, "ns")
	if entries, err := os.ReadDir(nsDir); err == nil {
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			link, linkErr := os.Readlink(filepath.Join(nsDir, ent.Name()))
			if linkErr != nil {
				continue
			}
			nsids[ent.Name()] = parseNSInode(link)
		}
	}

	startTime := time.Now().UTC()
	if st, err := os.Stat(procDir); err == nil {
		startTime = st.ModTime().UTC()
	}

	return &ProcessInfo{
		PID:       pid,
		PPID:      ppid,
		Comm:      comm,
		ExePath:   exePath,
		Cmdline:   cmdline,
		StartTime: startTime,
		UID:       uid,
		GID:       gid,
		Cgroups:   cgroups,
		NSIDs:     nsids,
	}, nil
}

func (p *ProcEnricher) readFDs(ctx context.Context, pid uint32, inodeMap map[uint64]NetConn) ([]FDInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pidStr := strconv.FormatUint(uint64(pid), 10)
	fdDir := filepath.Join(p.procRoot, pidStr, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	out := make([]FDInfo, 0, len(entries))
	for _, ent := range entries {
		select {
		case <-ctx.Done():
			return out, nil
		default:
		}

		fdNum, convErr := strconv.Atoi(ent.Name())
		if convErr != nil {
			continue
		}

		target, linkErr := os.Readlink(filepath.Join(fdDir, ent.Name()))
		if linkErr != nil {
			continue
		}

		info := FDInfo{FD: fdNum, Target: target, Type: detectFDType(target)}
		if m := socketInodeRe.FindStringSubmatch(target); len(m) == 2 {
			inode, _ := strconv.ParseUint(m[1], 10, 64)
			info.SocketInode = inode
			if conn, ok := inodeMap[inode]; ok {
				info.LocalAddr = conn.LocalAddr
				info.RemoteAddr = conn.RemoteAddr
			}
		}

		out = append(out, info)
	}

	return out, nil
}

func (p *ProcEnricher) readProcNetTCP(ctx context.Context, fileName, proto string, pid uint32) ([]NetConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	data, err := os.ReadFile(filepath.Join(p.procRoot, strconv.FormatUint(uint64(pid), 10), "net", fileName))
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) <= 1 {
		return nil, nil
	}

	out := make([]NetConn, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		local := parseHexAddr(fields[1])
		remote := parseHexAddr(fields[2])
		state := tcpState(fields[3])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		out = append(out, NetConn{
			Proto:      proto,
			LocalAddr:  local,
			RemoteAddr: remote,
			State:      state,
			PID:        pid,
			Inode:      inode,
		})
	}

	return out, nil
}

func parseHexAddr(v string) string {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return v
	}
	addrHex, portHex := parts[0], parts[1]

	port, _ := strconv.ParseUint(portHex, 16, 16)
	if len(addrHex) == 8 {
		b1, _ := strconv.ParseUint(addrHex[6:8], 16, 8)
		b2, _ := strconv.ParseUint(addrHex[4:6], 16, 8)
		b3, _ := strconv.ParseUint(addrHex[2:4], 16, 8)
		b4, _ := strconv.ParseUint(addrHex[0:2], 16, 8)
		ip := net.IPv4(byte(b1), byte(b2), byte(b3), byte(b4)).String()
		return fmt.Sprintf("%s:%d", ip, port)
	}

	if len(addrHex) == 32 {
		ipBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			b, _ := strconv.ParseUint(addrHex[i*2:(i+1)*2], 16, 8)
			ipBytes[i] = byte(b)
		}
		return fmt.Sprintf("%s:%d", net.IP(ipBytes).String(), port)
	}

	return fmt.Sprintf("%s:%d", addrHex, port)
}

func tcpState(v string) string {
	stateMap := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if s, ok := stateMap[strings.ToUpper(v)]; ok {
		return s
	}
	return v
}

func detectFDType(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:"):
		return "socket"
	case strings.HasPrefix(target, "pipe:"):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon_inode"
	default:
		return "file"
	}
}

func parseNSInode(s string) uint64 {
	start := strings.IndexByte(s, '[')
	end := strings.IndexByte(s, ']')
	if start == -1 || end == -1 || end <= start+1 {
		return 0
	}
	v, _ := strconv.ParseUint(s[start+1:end], 10, 64)
	return v
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return v
}
