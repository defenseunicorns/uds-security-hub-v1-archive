package types

type MockLogger struct{}

func (m *MockLogger) Debug(msg string, fields ...interface{})  {}
func (m *MockLogger) Info(msg string, fields ...interface{})   {}
func (m *MockLogger) Warn(msg string, fields ...interface{})   {}
func (m *MockLogger) Error(msg string, fields ...interface{})  {}
func (m *MockLogger) Fatalf(msg string, fields ...interface{}) {}
