package integration

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/alert"
	"github.com/yoursec/rsbp/internal/correlation"
	"github.com/yoursec/rsbp/internal/detection"
	"github.com/yoursec/rsbp/internal/enrichment"
	"github.com/yoursec/rsbp/internal/types"
)

type EventInjector struct {
	input chan types.SyscallEvent
}

func NewEventInjector(buf int) *EventInjector {
	if buf <= 0 {
		buf = 64
	}
	return &EventInjector{input: make(chan types.SyscallEvent, buf)}
}

func (e *EventInjector) Input() chan<- types.SyscallEvent {
	return e.input
}

func (e *EventInjector) Inject(events []types.SyscallEvent) {
	for _, ev := range events {
		e.input <- ev
	}
}

func (e *EventInjector) Close() {
	close(e.input)
}

type Scenario struct {
	Name             string
	Events           []types.SyscallEvent
	ExpectedFired    bool
	ExpectedSeverity types.AlertSeverity
	ExpectedMITRE    []string
}

func RunScenario(t *testing.T, scenario Scenario) {
	t.Helper()

	sessionOut := make(chan *correlation.SessionState, 16)
	corr := correlation.New(5*time.Second, sessionOut, zap.NewNop())
	injector := NewEventInjector(len(scenario.Events) + 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go corr.Run(ctx, injector.input)

	injector.Inject(scenario.Events)
	injector.Close()
	time.Sleep(30 * time.Millisecond)

	var session *correlation.SessionState
	drain := true
	for drain {
		select {
		case s := <-sessionOut:
			session = s
		default:
			drain = false
		}
	}

	if !scenario.ExpectedFired {
		if session != nil {
			t.Fatalf("scenario %q unexpectedly emitted a correlated session", scenario.Name)
		}
		return
	}

	if session == nil {
		t.Fatalf("scenario %q did not emit a correlated session", scenario.Name)
	}

	detector := detection.NewEngine(detection.Config{
		ExecConnectWindowSeconds: 5,
		MinScore:                 0.55,
	}, zap.NewNop())
	last := scenario.Events[len(scenario.Events)-1]
	rawAlerts := detector.Evaluate(session, last, "integration-host")
	if len(rawAlerts) == 0 {
		t.Fatalf("scenario %q did not produce detection alert", scenario.Name)
	}

	mockEnrichment := &enrichment.Result{
		Country:              "US",
		City:                 "Ashburn",
		ASN:                  13335,
		ASNOrg:               "CLOUDFLARENET",
		ReputationScore:      90,
		AbuseConfidenceScore: 85,
	}

	builder := alert.NewBuilder("integration-host", "itest")
	finalAlert := builder.Build(session, &alert.DetectionResult{
		Severity:   rawAlerts[0].Severity,
		Score:      rawAlerts[0].Confidence,
		FiredRules: []string{rawAlerts[0].RuleID},
	}, mockEnrichment)
	if finalAlert == nil {
		t.Fatalf("scenario %q alert builder returned nil", scenario.Name)
	}

	if finalAlert.Severity != scenario.ExpectedSeverity {
		t.Fatalf("scenario %q severity mismatch: got=%s want=%s", scenario.Name, finalAlert.Severity, scenario.ExpectedSeverity)
	}

	for _, want := range scenario.ExpectedMITRE {
		if !hasMITRE(finalAlert.MITRETechniques, want) {
			t.Fatalf("scenario %q missing MITRE technique %s", scenario.Name, want)
		}
	}
}

func hasMITRE(techniques []alert.MITRETechnique, id string) bool {
	for _, tt := range techniques {
		if tt.ID == id {
			return true
		}
	}
	return false
}
