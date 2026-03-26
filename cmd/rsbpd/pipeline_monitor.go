package main

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type queueProbe struct {
	Name string
	Len  func() int
	Cap  int
}

type pipelineTracker struct {
	logger *zap.Logger

	eventsSeen      atomic.Uint64
	sessionsCreated atomic.Uint64
	alertsGenerated atomic.Uint64
	alertsEmitted   atomic.Uint64

	blockedChannelSends atomic.Uint64
	channelOverflowWarn atomic.Uint64
	deadPipelineWarn    atomic.Uint64

	syntheticRuns     atomic.Uint64
	syntheticFailures atomic.Uint64

	lastEventUnix   atomic.Int64
	lastSessionUnix atomic.Int64
	lastAlertUnix   atomic.Int64
	lastOutputUnix  atomic.Int64

	eventsPerSecondTimes100 atomic.Uint64

	mu               sync.RWMutex
	lastSyntheticErr string
}

func newPipelineTracker(logger *zap.Logger) *pipelineTracker {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &pipelineTracker{logger: logger}
}

func (p *pipelineTracker) markEvent() {
	p.eventsSeen.Add(1)
	p.lastEventUnix.Store(time.Now().Unix())
}

func (p *pipelineTracker) markSession() {
	p.sessionsCreated.Add(1)
	p.lastSessionUnix.Store(time.Now().Unix())
}

func (p *pipelineTracker) markAlertGenerated() {
	p.alertsGenerated.Add(1)
	p.lastAlertUnix.Store(time.Now().Unix())
}

func (p *pipelineTracker) markAlertEmitted() {
	p.alertsEmitted.Add(1)
	p.lastOutputUnix.Store(time.Now().Unix())
}

func (p *pipelineTracker) observeChannelSend(channel string, elapsed time.Duration) {
	if elapsed >= 200*time.Millisecond {
		p.blockedChannelSends.Add(1)
		p.logger.Warn("channel send appears blocked",
			zap.String("channel", channel),
			zap.Duration("send_latency", elapsed),
		)
	}
}

func (p *pipelineTracker) markSyntheticFailure(err error) {
	p.syntheticFailures.Add(1)
	p.mu.Lock()
	if err != nil {
		p.lastSyntheticErr = err.Error()
	} else {
		p.lastSyntheticErr = "unknown synthetic check failure"
	}
	p.mu.Unlock()
}

func (p *pipelineTracker) clearSyntheticFailure() {
	p.mu.Lock()
	p.lastSyntheticErr = ""
	p.mu.Unlock()
}

func (p *pipelineTracker) lastSyntheticError() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastSyntheticErr
}

func (p *pipelineTracker) startEPSMonitor(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	prev := p.eventsSeen.Load()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := p.eventsSeen.Load()
			delta := next - prev
			prev = next
			p.eventsPerSecondTimes100.Store(delta * 100)
		}
	}
}

func (p *pipelineTracker) startDeadPipelineMonitor(ctx context.Context, timeoutSeconds int) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	timeout := int64(timeoutSeconds)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			last := p.lastEventUnix.Load()
			if last == 0 {
				continue
			}
			if now-last >= timeout {
				p.deadPipelineWarn.Add(1)
				p.logger.Warn("pipeline appears stalled: no new eBPF events",
					zap.Int64("seconds_since_last_event", now-last),
					zap.Int("threshold_seconds", timeoutSeconds),
				)
			}
		}
	}
}

func (p *pipelineTracker) startQueueMonitor(ctx context.Context, probes []queueProbe) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, probe := range probes {
				if probe.Cap <= 0 || probe.Len == nil {
					continue
				}
				qLen := probe.Len()
				if qLen < (probe.Cap*8)/10 {
					continue
				}
				p.channelOverflowWarn.Add(1)
				p.logger.Warn("channel occupancy high",
					zap.String("channel", probe.Name),
					zap.Int("len", qLen),
					zap.Int("cap", probe.Cap),
				)
			}
		}
	}
}

func (p *pipelineTracker) startSyntheticChecks(ctx context.Context, intervalSeconds int) {
	if intervalSeconds <= 0 {
		intervalSeconds = 60
	}
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = p.runSyntheticCheck(ctx)
		}
	}
}

func (p *pipelineTracker) runSyntheticCheck(ctx context.Context) error {
	p.syntheticRuns.Add(1)

	beforeEvents := p.eventsSeen.Load()
	beforeSessions := p.sessionsCreated.Load()
	beforeAlerts := p.alertsGenerated.Load()
	beforeEmitted := p.alertsEmitted.Load()

	testCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(testCtx, "bash", "-c", "bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' >/dev/null 2>&1 || true")
	if err := cmd.Run(); err != nil {
		p.markSyntheticFailure(fmt.Errorf("synthetic command failed: %w", err))
		p.logger.Warn("synthetic pipeline check command failed", zap.Error(err))
		return err
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		eventsOK := p.eventsSeen.Load() > beforeEvents
		sessionsOK := p.sessionsCreated.Load() > beforeSessions
		alertsOK := p.alertsGenerated.Load() > beforeAlerts
		emittedOK := p.alertsEmitted.Load() > beforeEmitted
		if eventsOK && sessionsOK && alertsOK && emittedOK {
			p.clearSyntheticFailure()
			p.logger.Info("synthetic pipeline check passed",
				zap.Uint64("events_delta", p.eventsSeen.Load()-beforeEvents),
				zap.Uint64("sessions_delta", p.sessionsCreated.Load()-beforeSessions),
				zap.Uint64("alerts_delta", p.alertsGenerated.Load()-beforeAlerts),
				zap.Uint64("emitted_delta", p.alertsEmitted.Load()-beforeEmitted),
			)
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	err := fmt.Errorf("synthetic pipeline check failed: deltas events=%d sessions=%d alerts=%d emitted=%d",
		p.eventsSeen.Load()-beforeEvents,
		p.sessionsCreated.Load()-beforeSessions,
		p.alertsGenerated.Load()-beforeAlerts,
		p.alertsEmitted.Load()-beforeEmitted,
	)
	p.markSyntheticFailure(err)
	p.logger.Warn("synthetic pipeline check failed", zap.Error(err))
	return err
}

func (p *pipelineTracker) deepHealth(ebpfLoaded bool, ebpfLostEvents uint64) map[string]any {
	now := time.Now().Unix()
	lastEvent := p.lastEventUnix.Load()
	lastAlert := p.lastAlertUnix.Load()
	lastOutput := p.lastOutputUnix.Load()

	eventAge := int64(-1)
	if lastEvent > 0 {
		eventAge = now - lastEvent
	}
	alertAge := int64(-1)
	if lastAlert > 0 {
		alertAge = now - lastAlert
	}
	outputAge := int64(-1)
	if lastOutput > 0 {
		outputAge = now - lastOutput
	}

	return map[string]any{
		"ebpf_status": map[string]any{
			"loaded":        ebpfLoaded,
			"dropped_events": ebpfLostEvents,
		},
		"event_flow": map[string]any{
			"events_per_sec":             float64(p.eventsPerSecondTimes100.Load()) / 100.0,
			"events_total":               p.eventsSeen.Load(),
			"seconds_since_last_event":   eventAge,
			"dead_pipeline_warnings_total": p.deadPipelineWarn.Load(),
		},
		"detection_active": map[string]any{
			"sessions_created":         p.sessionsCreated.Load(),
			"alerts_generated":         p.alertsGenerated.Load(),
			"seconds_since_last_alert": alertAge,
		},
		"output_active": map[string]any{
			"alerts_emitted":                p.alertsEmitted.Load(),
			"seconds_since_last_output":     outputAge,
			"blocked_channel_sends_total":   p.blockedChannelSends.Load(),
			"channel_overflow_warnings_total": p.channelOverflowWarn.Load(),
		},
		"synthetic_check": map[string]any{
			"runs_total":     p.syntheticRuns.Load(),
			"failures_total": p.syntheticFailures.Load(),
			"last_error":     p.lastSyntheticError(),
		},
	}
}
