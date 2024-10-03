package scan

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// MockPackageScanner is a mock implementation of the PackageScanner interface.
type MockPackageScanner struct{}

func NewMockPackageScanner() *MockPackageScanner {
	return &MockPackageScanner{}
}

func TestCreateScanner_LocalPackage(t *testing.T) {
	sf := &ScannerFactoryImpl{}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	packagePath := "/path/to/package"

	scanner, err := sf.CreateScanner(context.Background(), logger, "", "", "", packagePath, "", nil, RootFSScannerType)
	require.NoError(t, err, "expected no error, got %v", err)
	require.NotNil(t, scanner, "expected non-nil scanner, got nil")
}

func TestCreateScanner_RemotePackage(t *testing.T) {
	sf := &ScannerFactoryImpl{}
	org := "exampleOrg"
	packageName := "examplePackage"
	tag := "latest"

	scanner, err := sf.CreateScanner(context.Background(), nil, org, packageName, tag, "", "", nil, RootFSScannerType)
	require.NoError(t, err, "expected no error, got %v", err)
	require.NotNil(t, scanner, "expected non-nil scanner, got nil")
}

func TestCreateScanner_MissingParameters(t *testing.T) {
	sf := &ScannerFactoryImpl{}

	_, err := sf.CreateScanner(context.Background(), nil, "", "", "", "", "", nil, RootFSScannerType)
	expectedErr := "org, packageName, and tag are required for remote scanning"
	require.Equal(t, expectedErr, err.Error(), "unexpected error (-want +got)")
}
