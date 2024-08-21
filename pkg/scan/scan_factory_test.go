package scan

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/defenseunicorns/uds-security-hub/internal/log"
)

// MockPackageScanner is a mock implementation of the PackageScanner interface.
type MockPackageScanner struct{}

func NewMockPackageScanner() *MockPackageScanner {
	return &MockPackageScanner{}
}

func TestCreateScanner_LocalPackage(t *testing.T) {
	sf := &ScannerFactoryImpl{}
	logger := log.NewLogger(context.Background())
	packagePath := "/path/to/package"

	scanner, err := sf.CreateScanner(context.Background(), logger, "", "", "", packagePath, "", nil, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if scanner == nil {
		t.Fatalf("expected non-nil scanner, got nil")
	}
}

func TestCreateScanner_RemotePackage(t *testing.T) {
	sf := &ScannerFactoryImpl{}
	org := "exampleOrg"
	packageName := "examplePackage"
	tag := "latest"

	scanner, err := sf.CreateScanner(context.Background(), nil, org, packageName, tag, "", "", nil, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if scanner == nil {
		t.Fatalf("expected non-nil scanner, got nil")
	}
}

func TestCreateScanner_MissingParameters(t *testing.T) {
	sf := &ScannerFactoryImpl{}

	_, err := sf.CreateScanner(context.Background(), nil, "", "", "", "", "", nil, false)
	expectedErr := "org, packageName, and tag are required for remote scanning"
	if diff := cmp.Diff(expectedErr, err.Error()); diff != "" {
		t.Errorf("unexpected error (-want +got):\n%s", diff)
	}
}
