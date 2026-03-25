package alert

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/yoursec/rsbp/internal/types"
)

type Sink interface {
	Send(ctx context.Context, alert *types.ReverseShellAlert) error
}

type Emitter struct {
	sink   Sink
	logger *zap.Logger
}

func NewEmitter(sink Sink, logger *zap.Logger) *Emitter {
	return &Emitter{sink: sink, logger: logger}
}

func (e *Emitter) Emit(ctx context.Context, alert *types.ReverseShellAlert) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	if e.sink == nil {
		return fmt.Errorf("sink is not configured")
	}

	if err := e.sink.Send(ctx, alert); err != nil {
		return err
	}

	e.logger.Debug("alert emitted",
		zap.String("alert_id", alert.AlertID),
		zap.String("severity", string(alert.Severity)),
	)

	return nil
}
