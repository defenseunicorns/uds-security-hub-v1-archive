package log

import (
	"bytes"
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// mockWriteSyncer is a mock implementation of the zapcore.WriteSyncer interface for testing purposes.
type mockWriteSyncer struct {
	buffer bytes.Buffer
}

func (m *mockWriteSyncer) Write(p []byte) (n int, err error) {
	return m.buffer.Write(p)
}

func (m *mockWriteSyncer) Sync() error {
	return nil
}

func TestNewLogger(t *testing.T) {
	ctx := context.Background()
	logger := NewLogger(ctx)
	if logger == nil {
		t.Fatal("Expected logger to be non-nil")
	}
}

func TestWithLogger(t *testing.T) {
	ctx := context.Background()
	logger := NewLogger(ctx)
	ctxWithLogger := WithLogger(ctx, logger)
	if ctxWithLogger.Value(loggerKey) == nil {
		t.Fatal("Expected logger to be set in context")
	}
}

func TestDebug(t *testing.T) {
	ctx := context.Background()
	logger := NewLogger(ctx).(*zapLogger) //nolint:errcheck
	mock := &mockWriteSyncer{}
	logger.logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), mock, zap.DebugLevel))

	logger.Debug("debug message")
	if !bytes.Contains(mock.buffer.Bytes(), []byte("debug message")) {
		t.Fatalf("Expected debug message to be logged, got %s", mock.buffer.String())
	}
}

func TestInfo(t *testing.T) {
	ctx := context.Background()
	logger := NewLogger(ctx).(*zapLogger) //nolint:errcheck
	mock := &mockWriteSyncer{}
	logger.logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), mock, zap.InfoLevel))

	logger.Info("info message")
	if !bytes.Contains(mock.buffer.Bytes(), []byte("info message")) {
		t.Fatalf("Expected info message to be logged, got %s", mock.buffer.String())
	}
}

func TestWarn(t *testing.T) {
	ctx := context.Background()
	logger := NewLogger(ctx).(*zapLogger) //nolint:errcheck
	mock := &mockWriteSyncer{}
	logger.logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), mock, zap.WarnLevel))

	logger.Warn("warn message")
	if !bytes.Contains(mock.buffer.Bytes(), []byte("warn message")) {
		t.Fatalf("Expected warn message to be logged, got %s", mock.buffer.String())
	}
}

func TestError(t *testing.T) {
	ctx := context.Background()
	logger := NewLogger(ctx).(*zapLogger) //nolint:errcheck
	mock := &mockWriteSyncer{}
	logger.logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), mock, zap.ErrorLevel))

	logger.Error("error message")
	if !bytes.Contains(mock.buffer.Bytes(), []byte("error message")) {
		t.Fatalf("Expected error message to be logged, got %s", mock.buffer.String())
	}
}
