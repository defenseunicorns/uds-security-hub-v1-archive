package types

// Logger is the interface that the logger must implement.
type Logger interface {
	// Debug logs a debug message with the given fields.
	Debug(msg string, fields ...interface{})
	// Info logs an info message with the given fields.
	Info(msg string, fields ...interface{})
	// Warn logs a warn message with the given fields.
	Warn(msg string, fields ...interface{})
	// Error logs an error message with the given fields.
	Error(msg string, fields ...interface{})
	// Fatalf logs a fatal message with the given fields.
	Fatalf(msg string, fields ...interface{})
}
