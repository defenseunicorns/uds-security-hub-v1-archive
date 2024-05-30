package log

import (
	"context"

	"go.uber.org/zap"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// zapLogger is a struct that implements the Logger interface.
type zapLogger struct {
	logger *zap.Logger
}

// contextKey is the key used to store the logger in the context.
type contextKey string

// loggerKey is the key used to store the logger in the context.
const loggerKey contextKey = "logger"

// NewLogger returns a new logger instance.
// This func will panic if the context is nil or if it cannot create a new logger.
func NewLogger(ctx context.Context) types.Logger {
	if ctx == nil {
		panic("ctx cannot be nil")
	}
	if logger, ok := ctx.Value(loggerKey).(types.Logger); ok {
		return logger
	}
	zapLoggerInstance, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	newLogger := &zapLogger{logger: zapLoggerInstance}
	WithLogger(ctx, newLogger)
	return newLogger
}

// WithLogger returns a new context with the logger set.
// This func will panic if the context is nil.
func WithLogger(ctx context.Context, logger types.Logger) context.Context {
	if ctx == nil {
		panic("ctx cannot be nil")
	}
	return context.WithValue(ctx, loggerKey, logger)
}

// Debug logs a debug message with the given fields.
func (l *zapLogger) Debug(msg string, fields ...interface{}) {
	var zapFields []zap.Field
	for _, field := range fields {
		if zf, ok := field.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	l.logger.Debug(msg, zapFields...)
}

// Info logs an info message with the given fields.
func (l *zapLogger) Info(msg string, fields ...interface{}) {
	var zapFields []zap.Field
	for _, field := range fields {
		if zf, ok := field.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	l.logger.Info(msg, zapFields...)
}

// Warn logs a warn message with the given fields.
func (l *zapLogger) Warn(msg string, fields ...interface{}) {
	var zapFields []zap.Field
	for _, field := range fields {
		if zf, ok := field.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	l.logger.Warn(msg, zapFields...)
}

// Error logs an error message with the given fields.
func (l *zapLogger) Error(msg string, fields ...interface{}) {
	var zapFields []zap.Field
	for _, field := range fields {
		if zf, ok := field.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	l.logger.Error(msg, zapFields...)
}

// Fatalf logs a fatal message with the given fields.
func (l *zapLogger) Fatalf(msg string, fields ...interface{}) {
	var zapFields []zap.Field
	for _, field := range fields {
		if zf, ok := field.(zap.Field); ok {
			zapFields = append(zapFields, zf)
		}
	}
	l.logger.Fatal(msg, zapFields...)
}
