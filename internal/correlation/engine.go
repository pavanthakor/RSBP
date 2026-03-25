package correlation

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/types"
)

const (
	sysExecve  = 59
	sysSocket  = 41
	sysConnect = 42
	sysDup2    = 33
	sysDup3    = 292
	sysFork    = 57
	sysClone3  = 435
	sysPipe    = 22
	sysPipe2   = 293
)

var devTCPPattern = regexp.MustCompile(`bash.*-i.*>&.*/dev/tcp/(\d+\.\d+\.\d+\.\d+)/(\d+)`)

var (
	correlationMetricsOnce sync.Once
	sessionsActiveGauge    = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "rsbp",
		Name:      "sessions_active",
		Help:      "Currently active correlation sessions.",
	})
	sessionsCompletedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "sessions_completed_total",
		Help:      "Total completed correlation sessions by detected pattern.",
	}, []string{"pattern"})
	sessionsExpiredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "sessions_expired_total",
		Help:      "Total expired correlation sessions by reason.",
	}, []string{"reason"})
	channelDropsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rsbp",
		Name:      "channel_drops_total",
		Help:      "Total sessions dropped due to full output channel.",
	})
)

type MetricsSnapshot struct {
	SessionsActive    int
	SessionsCompleted uint64
	SessionsExpired   uint64
	ChannelDrops      uint64
}

type parentSocketState struct {
	SocketFD   int32
	RemoteIP   net.IP
	RemotePort uint16
	UpdatedAt  time.Time
}

type Engine struct {
	sessions        sync.Map
	emittedSessions sync.Map
	parentSocketMap sync.Map
	forkSeen        sync.Map
	pipeSeen        sync.Map
	windowDuration  time.Duration
	ticker          *time.Ticker
	output          chan<- *SessionState
	logger          *zap.Logger

	sessionsCompletedCount atomic.Uint64
	sessionsExpiredCount   atomic.Uint64
	channelDropCount       atomic.Uint64
}

const emittedSessionTTL = 5 * time.Minute

func New(window time.Duration, out chan<- *SessionState, log *zap.Logger) *Engine {
	if window <= 0 {
		window = 5 * time.Second
	}
	if log == nil {
		log = zap.NewNop()
	}

	correlationMetricsOnce.Do(func() {
		_ = prometheus.Register(sessionsActiveGauge)
		_ = prometheus.Register(sessionsCompletedTotal)
		_ = prometheus.Register(sessionsExpiredTotal)
		_ = prometheus.Register(channelDropsTotal)
	})

	return &Engine{
		windowDuration: window,
		ticker:         time.NewTicker(30 * time.Second),
		output:         out,
		logger:         log,
	}
}

func (e *Engine) Process(event types.SyscallEvent) {
	if e == nil {
		return
	}
	e.logger.Info("DEBUG CORRELATION RECEIVED",
		zap.String("comm", "received"),
		zap.Uint32("pid", event.PID),
	)

	e.logger.Debug("correlation received event",
		zap.Uint32("pid", event.PID),
		zap.Uint32("syscall_nr", event.SyscallNr),
	)

	pid := event.PID
	now := timestampToTime(event.TimestampNS)

	session := e.getOrCreateSession(event, now)
	if session.FirstEventAt.IsZero() {
		if !event.ReceivedAt.IsZero() {
			session.FirstEventAt = event.ReceivedAt.UTC()
		} else {
			session.FirstEventAt = now
		}
	}
	session.PPID = event.PPID
	session.UID = event.UID
	session.GID = event.GID
	session.LastUpdate = now

	e.upsertProcessNode(session, event, now)

	switch event.SyscallNr {
	case sysExecve:
		session.HasExecve = true
		exe := cString(event.ExecPath[:])
		args := cString(event.Args[:])
		if exe != "" {
			session.ExePath = exe
		} else {
			session.ExePath = commToString(event.Comm)
		}
		if args != "" {
			session.Cmdline = args
		}

		if inherited, ok := e.parentSocketMap.Load(session.PPID); ok {
			p := inherited.(parentSocketState)
			if !session.HasSocket && p.SocketFD >= 0 {
				session.SocketFD = p.SocketFD
				session.HasSocket = true
			}
			if !session.HasConnect && p.RemoteIP != nil && p.RemotePort != 0 {
				session.RemoteIP = append(net.IP(nil), p.RemoteIP...)
				session.RemotePort = p.RemotePort
				session.HasConnect = true
			}
		}

	case sysSocket:
		session.HasSocket = true
		session.SocketFD = event.FD
		e.parentSocketMap.Store(pid, parentSocketState{
			SocketFD:  event.FD,
			UpdatedAt: now,
		})

	case sysConnect:
		session.HasConnect = true
		session.SocketFD = event.FD
		ip := ipFromFields(event.Family, event.RemoteIP4, event.RemoteIP6)
		if ip != nil {
			session.RemoteIP = ip
		}
		if event.RemotePort != 0 {
			session.RemotePort = event.RemotePort
		}
		e.parentSocketMap.Store(pid, parentSocketState{
			SocketFD:   session.SocketFD,
			RemoteIP:   append(net.IP(nil), session.RemoteIP...),
			RemotePort: session.RemotePort,
			UpdatedAt:  now,
		})

		if parentAny, ok := e.sessions.Load(session.PPID); ok && isPublicRemoteIP(session.RemoteIP) {
			if parent, ok := parentAny.(*SessionState); ok && parent != nil {
				parent.HasConnect = true
				if parent.SocketFD < 0 && session.SocketFD >= 0 {
					parent.SocketFD = session.SocketFD
				}
				if session.RemoteIP != nil {
					parent.RemoteIP = append(net.IP(nil), session.RemoteIP...)
				}
				if session.RemotePort != 0 {
					parent.RemotePort = session.RemotePort
				}
				parent.LastUpdate = now
				e.sessions.Store(parent.PID, parent)
				e.parentSocketMap.Store(parent.PID, parentSocketState{
					SocketFD:   parent.SocketFD,
					RemoteIP:   append(net.IP(nil), parent.RemoteIP...),
					RemotePort: parent.RemotePort,
					UpdatedAt:  now,
				})
			}
		}

	case sysDup2, sysDup3:
		if event.HasDup2Stdio != 0 {
			session.HasDupToStdio = true
		}

	case sysFork, sysClone3:
		e.forkSeen.Store(pid, true)
		if _, ok := e.pipeSeen.Load(pid); ok {
			session.HasForkWithPipe = true
		}

	case sysPipe, sysPipe2:
		e.pipeSeen.Store(pid, true)
		if _, ok := e.forkSeen.Load(pid); ok {
			session.HasForkWithPipe = true
		}
	}

	session.Category = session.CategoryDetect()
	e.sessions.Store(pid, session)
	e.logDebugSessionState(event, session)

	complete := session.IsComplete()
	if complete {
		e.logger.Info("SESSION COMPLETE - emitting alert",
			zap.Uint32("pid", session.PID),
			zap.String("exe", session.ExePath),
		)
	}

	e.maybeEmit(session, complete)
	e.updateSessionsActiveGauge()
}

func (e *Engine) logDebugSessionState(event types.SyscallEvent, session *SessionState) {
	if e == nil || e.logger == nil || session == nil {
		return
	}
	comm := strings.ToLower(strings.TrimSpace(commToString(event.Comm)))
	if comm == "" {
		comm = strings.ToLower(strings.TrimSpace(session.ProcessName()))
	}
	if !isDebugShellTool(comm) {
		return
	}

	remoteIP := "<nil>"
	if session.RemoteIP != nil {
		remoteIP = session.RemoteIP.String()
	}

	e.logger.Info("DEBUG SESSION STATE",
		zap.String("comm", comm),
		zap.Uint32("pid", session.PID),
		zap.Bool("has_execve", session.HasExecve),
		zap.Bool("has_socket", session.HasSocket),
		zap.Bool("has_connect", session.HasConnect),
		zap.Bool("has_dup2_stdio", session.HasDupToStdio),
		zap.String("remote_ip", remoteIP),
		zap.Uint16("remote_port", session.RemotePort),
		zap.Float64("score", debugSessionScore(session)),
	)
}

func debugSessionScore(s *SessionState) float64 {
	if s == nil {
		return 0
	}
	score := 0.0
	if s.HasExecve {
		score += 0.25
	}
	if s.HasSocket {
		score += 0.20
	}
	if s.HasConnect {
		score += 0.25
	}
	if s.HasDupToStdio {
		score += 0.30
	}
	if score > 1 {
		score = 1
	}
	return score
}

func isDebugShellTool(comm string) bool {
	switch strings.ToLower(strings.TrimSpace(comm)) {
	case "bash", "sh", "python3", "nc":
		return true
	default:
		return false
	}
}

func (e *Engine) maybeEmit(session *SessionState, complete bool) {
	if e == nil || session == nil || e.output == nil {
		return
	}
	e.cleanupEmitted(time.Now())
	if session.LastUpdate.Sub(session.StartTime) > e.windowDuration {
		sessionsExpiredTotal.WithLabelValues("timeout").Inc()
		e.sessionsExpiredCount.Add(1)
		return
	}
	if !complete {
		return
	}

	key := emittedSessionKey(session)
	if _, alreadyEmitted := e.emittedSessions.LoadOrStore(key, time.Now()); alreadyEmitted {
		sessionsExpiredTotal.WithLabelValues("dedup").Inc()
		e.sessionsExpiredCount.Add(1)
		return
	}

	copyState := deepCopySession(session)
	patternName := sessionPatternName(copyState)
	select {
	case e.output <- copyState:
		sessionsCompletedTotal.WithLabelValues(patternName).Inc()
		e.sessionsCompletedCount.Add(1)
	default:
		channelDropsTotal.Inc()
		e.channelDropCount.Add(1)
		e.logger.Warn("output channel full, dropping session", zap.Uint32("pid", session.PID))
	}
}

func (e *Engine) cleanup() {
	if e == nil {
		return
	}

	cutoff := time.Now().Add(-2 * e.windowDuration)
	e.sessions.Range(func(key, value any) bool {
		pid, ok := key.(uint32)
		if !ok {
			return true
		}
		session, ok := value.(*SessionState)
		if !ok {
			e.sessions.Delete(key)
			return true
		}

		if session.LastUpdate.Before(cutoff) && !session.IsComplete() {
			e.sessions.Delete(pid)
			e.parentSocketMap.Delete(pid)
			e.forkSeen.Delete(pid)
			e.pipeSeen.Delete(pid)
		}
		return true
	})
	e.cleanupEmitted(time.Now())
	e.updateSessionsActiveGauge()
}

func (e *Engine) cleanupEmitted(now time.Time) {
	e.emittedSessions.Range(func(key, value any) bool {
		ts, ok := value.(time.Time)
		if !ok || time.Since(ts) > emittedSessionTTL {
			e.emittedSessions.Delete(key)
		}
		return true
	})
}

func emittedSessionKey(session *SessionState) string {
	if session == nil {
		return ""
	}
	remoteIP := ""
	if session.RemoteIP != nil {
		remoteIP = session.RemoteIP.String()
	}
	pattern := ""
	if p := BestMatchPattern(session); p != nil {
		pattern = p.Name
	}
	if pattern == "" {
		pattern = fmt.Sprintf("cat-%d", session.CategoryDetect())
	}
	return fmt.Sprintf("%d|%s|%s", session.PID, remoteIP, pattern)
}

func (e *Engine) Run(ctx context.Context, events <-chan types.SyscallEvent) {
	if e == nil {
		return
	}

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.ticker.C:
				e.cleanup()
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			e.ticker.Stop()
			<-cleanupDone
			return
		case ev, ok := <-events:
			if !ok {
				e.ticker.Stop()
				<-cleanupDone
				return
			}
			e.logger.Info("DEBUG CORRELATION RECEIVED",
				zap.String("comm", "received"),
				zap.Uint32("pid", ev.PID),
			)
			e.Process(ev)
		}
	}
}

func (e *Engine) getOrCreateSession(event types.SyscallEvent, now time.Time) *SessionState {
	if existing, ok := e.sessions.Load(event.PID); ok {
		if s, castOK := existing.(*SessionState); castOK {
			return s
		}
	}

	s := &SessionState{
		PID:         event.PID,
		PPID:        event.PPID,
		UID:         event.UID,
		GID:         event.GID,
		SocketFD:    -1,
		StartTime:   now,
		LastUpdate:  now,
		ProcessTree: make([]ProcessNode, 0, 4),
	}
	e.sessions.Store(event.PID, s)
	return s
}

func (e *Engine) upsertProcessNode(session *SessionState, event types.SyscallEvent, now time.Time) {
	if session == nil {
		return
	}
	if len(session.ProcessTree) > 0 {
		last := session.ProcessTree[len(session.ProcessTree)-1]
		if last.PID == event.PID && last.PPID == event.PPID {
			return
		}
	}

	session.ProcessTree = append(session.ProcessTree, ProcessNode{
		PID:       event.PID,
		PPID:      event.PPID,
		Comm:      commToString(event.Comm),
		ExePath:   cString(event.ExecPath[:]),
		StartTime: now,
	})
}

func deepCopySession(in *SessionState) *SessionState {
	if in == nil {
		return nil
	}
	out := *in
	if in.RemoteIP != nil {
		out.RemoteIP = append(net.IP(nil), in.RemoteIP...)
	}
	out.ProcessTree = append([]ProcessNode(nil), in.ProcessTree...)
	return &out
}

func timestampToTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Now().UTC()
	}
	return time.Unix(0, int64(ns)).UTC()
}

func ipFromFields(family uint16, ip4 uint32, ip6 [16]byte) net.IP {
	if family == 2 {
		if ip4 == 0 {
			return nil
		}
		v4 := []byte{byte(ip4), byte(ip4 >> 8), byte(ip4 >> 16), byte(ip4 >> 24)}
		return net.IPv4(v4[0], v4[1], v4[2], v4[3])
	}
	if family == 10 {
		allZero := true
		for i := 0; i < 16; i++ {
			if ip6[i] != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return nil
		}
		ip := make(net.IP, 16)
		copy(ip, ip6[:])
		return ip
	}
	return nil
}

func commToString(in [16]byte) string {
	b := in[:]
	for i := range b {
		if b[i] == 0 {
			return strings.TrimSpace(string(b[:i]))
		}
	}
	return strings.TrimSpace(string(b))
}

func cString(buf []byte) string {
	for i := range buf {
		if buf[i] == 0 {
			buf = buf[:i]
			break
		}
	}
	return strings.TrimSpace(string(buf))
}

type Tracker struct {
	engine *Engine
}

func NewTracker(ttl time.Duration) *Tracker {
	return NewTrackerWithLogger(ttl, zap.NewNop())
}

func NewTrackerWithLogger(ttl time.Duration, logger *zap.Logger) *Tracker {
	return &Tracker{engine: New(ttl, nil, logger)}
}

func (t *Tracker) Consume(ev types.SyscallEvent) *SessionState {
	if t == nil || t.engine == nil {
		return nil
	}
	t.engine.Process(ev)
	v, ok := t.engine.sessions.Load(ev.PID)
	if !ok {
		return nil
	}
	s, ok := v.(*SessionState)
	if !ok {
		return nil
	}
	copyState := deepCopySession(s)
	if copyState == nil {
		return nil
	}
	copyState.Category = copyState.CategoryDetect()
	if !copyState.IsComplete() {
		return copyState
	}

	t.engine.cleanupEmitted(time.Now())
	key := emittedSessionKey(copyState)
	if _, alreadyEmitted := t.engine.emittedSessions.LoadOrStore(key, time.Now()); alreadyEmitted {
		return nil
	}
	return copyState
}

func (t *Tracker) Snapshot(pid uint32) (string, bool) {
	if t == nil || t.engine == nil {
		return "", false
	}
	return t.engine.DebugSnapshot(pid)
}

func (e *Engine) DebugSnapshot(pid uint32) (string, bool) {
	v, ok := e.sessions.Load(pid)
	if !ok {
		return "", false
	}
	s, ok := v.(*SessionState)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("pid=%d ppid=%d category=%d complete=%t", s.PID, s.PPID, s.CategoryDetect(), s.IsComplete()), true
}

func (e *Engine) MetricsSnapshot() MetricsSnapshot {
	if e == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		SessionsActive:    e.activeSessionsCount(),
		SessionsCompleted: e.sessionsCompletedCount.Load(),
		SessionsExpired:   e.sessionsExpiredCount.Load(),
		ChannelDrops:      e.channelDropCount.Load(),
	}
}

func (e *Engine) updateSessionsActiveGauge() {
	if e == nil {
		return
	}
	sessionsActiveGauge.Set(float64(e.activeSessionsCount()))
}

func (e *Engine) activeSessionsCount() int {
	if e == nil {
		return 0
	}
	count := 0
	e.sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func sessionPatternName(session *SessionState) string {
	if p := BestMatchPattern(session); p != nil && strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return "unknown"
}
