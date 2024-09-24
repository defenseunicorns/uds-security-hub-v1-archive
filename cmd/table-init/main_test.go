package main

import (
	"context"
	"testing"

	"github.com/jaekwon/testify/require"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

func TestGetEnv(t *testing.T) {
	// Test when environment variable exists
	t.Setenv("TEST_KEY", "test_value")
	assert.Equal(t, "test_value", getEnv("TEST_KEY", "default"))

	// Test when environment variable doesn't exist
	assert.Equal(t, "default", getEnv("NON_EXISTENT_KEY", "default"))
}

func TestGetConfig(t *testing.T) {
	// Set test environment variables
	t.Setenv("DB_HOST", "testhost")
	t.Setenv("DB_PORT", "1234")
	t.Setenv("DB_USER", "testuser")
	t.Setenv("DB_PASSWORD", "testpass")
	t.Setenv("DB_NAME", "testdb")
	t.Setenv("INSTANCE_CONNECTION_NAME", "testinstance")

	config := getConfig()

	assert.Equal(t, "testhost", config.DBHost)
	assert.Equal(t, "1234", config.DBPort)
	assert.Equal(t, "testuser", config.DBUser)
	assert.Equal(t, "testpass", config.DBPassword)
	assert.Equal(t, "testdb", config.DBName)
	assert.Equal(t, "testinstance", config.DBInstanceConnectionName)
}

// MockDBConnector is a mock implementation of sql.DBConnector.
type MockDBConnector struct {
	mock.Mock
}

func (m *MockDBConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	args := m.Called(ctx)
	return args.Get(0).(*gorm.DB), args.Error(1)
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	config := sql.DatabaseConfig{
		DBHost:                   "testhost",
		DBPort:                   "1234",
		DBUser:                   "testuser",
		DBPassword:               "testpass",
		DBName:                   "testdb",
		DBInstanceConnectionName: "testinstance",
	}

	mockDB := &gorm.DB{}
	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return(mockDB, nil)

	mockConnectorFactory := func(*sql.DatabaseConfig) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return nil
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)

	require.NoError(t, err)
	mockConnector.AssertExpectations(t)
}

func TestRunWithConnectError(t *testing.T) {
	ctx := context.Background()
	config := sql.DatabaseConfig{}

	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return((*gorm.DB)(nil), assert.AnError)

	mockConnectorFactory := func(*sql.DatabaseConfig) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return nil
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to connect to database")
	mockConnector.AssertExpectations(t)
}

func TestRunWithMigrateError(t *testing.T) {
	ctx := context.Background()
	config := sql.DatabaseConfig{}

	mockDB := &gorm.DB{}
	mockConnector := new(MockDBConnector)
	mockConnector.On("Connect", ctx).Return(mockDB, nil)

	mockConnectorFactory := func(*sql.DatabaseConfig) sql.DBConnector {
		return mockConnector
	}

	mockMigrator := func(*gorm.DB) error {
		return assert.AnError
	}

	err := run(ctx, &config, mockConnectorFactory, mockMigrator)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to migrate database")
	mockConnector.AssertExpectations(t)
}
