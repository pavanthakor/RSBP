package logging

import "go.uber.org/zap"

func WithAlertID(logger *zap.Logger, alertID string) *zap.Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	if alertID == "" {
		return logger
	}
	return logger.With(zap.String("correlation_id", alertID))
}

func WithStage(logger *zap.Logger, stage string) *zap.Logger {
	if logger == nil {
		logger = zap.NewNop()
	}
	if stage == "" {
		return logger
	}
	return logger.With(zap.String("pipeline_stage", stage))
}

func PipelineLogger(base *zap.Logger, alertID, stage string) *zap.Logger {
	return WithStage(WithAlertID(base, alertID), stage)
}
