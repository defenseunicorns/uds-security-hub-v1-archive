package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

var (
	errConnectFailed = errors.New("failed to connect to database")
	errMigrateFailed = errors.New("failed to migrate database")
)

func TestGetEnv(t *testing.T) {
	// Test when environment variable exists
	t.Setenv("TEST_KEY", "test_value")
	got := getEnv("TEST_KEY", "default")
	want := "test_value"
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("getEnv() mismatch (-want +got):\n%s", diff)
	}

	// Test when environment variable doesn't exist
	got = getEnv("NON_EXISTENT_KEY", "default")
	want = "default"
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("getEnv() mismatch (-want +got):\n%s", diff)
	}
}

func TestGetConfig(t *testing.T) {
	// Set test environment variables
	t.Setenv("DB_HOST", "testhost")
	t.Setenv("DB_PORT", "1234")
	t.Setenv("DB_USER", "testuser")
	t.Setenv("DB_PASSWORD", "testpass")
	t.Setenv("DB_NAME", "testdb")
	t.Setenv("INSTANCE_CONNECTION_NAME", "testinstance")

	got := getConfig()
	want := Config{
		Host:                   "testhost",
		Port:                   "1234",
		User:                   "testuser",
		Password:               "testpass",
		DBName:                 "testdb",
		InstanceConnectionName: "testinstance",
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("getConfig() mismatch (-want +got):\n%s", diff)
	}
}

// MockDBConnector is a mock implementation of sql.DBConnector.
type MockDBConnector struct {
	mock.Mock
}

func (m *MockDBConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	args := m.Called(ctx)
	if db, ok := args.Get(0).(*gorm.DB); ok {
		return db, args.Error(1)
	}
	return nil, args.Error(1)
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	config := Config{
		Host:                   "testhost",
		Port:                   "1234",
		User:                   "testuser",
		Password:               "testpass",
		DBName:                 "testdb",
		InstanceConnectionName: "testinstance",
	}

	mockDB := &gorm.DB{}
	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return(mockDB, nil)

	mockConnectorFactory := func(string, string, string, string, string, string) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return nil
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)
	if err != nil {
		t.Fatalf("run() returned unexpected error: %v", err)
	}
	mockConnector.AssertExpectations(t)
}

func TestRunWithConnectError(t *testing.T) {
	ctx := context.Background()
	config := Config{}

	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return((*gorm.DB)(nil), errConnectFailed)

	mockConnectorFactory := func(string, string, string, string, string, string) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return nil
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)
	if err == nil {
		t.Fatalf("run() expected to return an error, got nil")
	}
	if !errors.Is(err, errConnectFailed) {
		t.Errorf("run() error mismatch. Want %v, got %v", errConnectFailed, err)
	}
	mockConnector.AssertExpectations(t)
}

func TestRunWithMigrateError(t *testing.T) {
	ctx := context.Background()
	config := Config{}

	mockDB := &gorm.DB{}
	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return(mockDB, nil)

	mockConnectorFactory := func(string, string, string, string, string, string) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return errMigrateFailed
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)
	if err == nil {
		t.Fatalf("run() expected to return an error, got nil")
	}
	if !errors.Is(err, errMigrateFailed) {
		t.Errorf("run() error mismatch. Want %v, got %v", errMigrateFailed, err)
	}
	mockConnector.AssertExpectations(t)
}

func TestMigrateDatabase(t *testing.T) {
	// Create an in-memory SQLite database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to in-memory database: %v", err)
	}

	// Run the migration
	err = migrateDatabase(db)
	if err != nil {
		t.Fatalf("failed to migrate database: %v", err)
	}

	// Check if tables were created
	for _, table := range []interface{}{&model.Package{}, &model.Scan{}, &model.Vulnerability{}} {
		if !db.Migrator().HasTable(table) {
			t.Errorf("table for model %T was not created", table)
		}
	}
}
