package scan

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{})  {}
func (m *mockLogger) Info(msg string, fields ...interface{})   {}
func (m *mockLogger) Warn(msg string, fields ...interface{})   {}
func (m *mockLogger) Error(msg string, fields ...interface{})  {}
func (m *mockLogger) Fatalf(msg string, fields ...interface{}) {}

func TestNewLocalPackageScanner(t *testing.T) {
	logger := &mockLogger{}
	packagePath := "/path/to/package"

	tests := []struct {
		logger      types.Logger
		expected    *LocalPackageScanner
		name        string
		packagePath string
		scannerType ScannerType
		expectError bool
	}{
		{
			name:        "valid inputs",
			logger:      logger,
			packagePath: packagePath,
			scannerType: SBOMScannerType,
			expected: &LocalPackageScanner{
				logger:      logger,
				packagePath: packagePath,
				scannerType: SBOMScannerType,
			},
			expectError: false,
		},
		{
			name:        "valid inputs for rootfs",
			logger:      logger,
			packagePath: packagePath,
			scannerType: SBOMScannerType,
			expected: &LocalPackageScanner{
				logger:      logger,
				packagePath: packagePath,
				scannerType: SBOMScannerType,
			},
			expectError: false,
		},
		{
			name:        "empty packagePath",
			logger:      logger,
			packagePath: "",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "nil logger",
			logger:      nil,
			packagePath: packagePath,
			expected:    nil,
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewLocalPackageScanner(tt.logger, tt.packagePath, "", tt.scannerType)
			checkError(t, err, tt.expectError)
			if !tt.expectError {
				if diff := cmp.Diff(tt.expected, scanner, cmp.AllowUnexported(LocalPackageScanner{})); diff != "" {
					t.Errorf("scanner mismatch (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func TestScanImageE2E(t *testing.T) {
	const zarfPackagePath = "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"
	ctx := context.Background()
	logger := log.NewLogger(ctx)

	type testCase struct {
		name        string
		scannerType ScannerType
	}

	testCases := []testCase{
		{
			name:        "SBOM",
			scannerType: SBOMScannerType,
		},
		{
			name:        "RootFS",
			scannerType: RootFSScannerType,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			lps, err := NewLocalPackageScanner(logger, zarfPackagePath, "", tt.scannerType)
			if err != nil {
				t.Fatalf("Failed to create local package scanner: %v", err)
			}
			result, err := lps.Scan(ctx)
			if err != nil {
				t.Fatalf("Failed to scan image: %v", err)
			}
			reader, err := lps.ScanResultReader(result[0])
			if err != nil {
				t.Fatalf("Failed to get scan result reader: %v", err)
			}
			artifactName := reader.GetArtifactName()
			if artifactName == "" {
				t.Fatalf("Expected artifact name to be non-empty, got %s", artifactName)
			}
			vulnerabilities := reader.GetVulnerabilities()
			if len(vulnerabilities) == 0 {
				t.Fatalf("Expected non-empty vulnerabilities, got empty")
			}
			var buf bytes.Buffer
			if err := WriteToJSON(&buf, []types.ScanResultReader{reader}); err != nil {
				t.Fatalf("Error writing JSON: %v", err)
			}
			jsonOutput := buf.String()
			if jsonOutput == "" {
				t.Fatalf("Expected non-empty JSON, got empty")
			}
			buf.Reset() // Reset buffer for CSV writing

			if err := WriteToCSV(&buf, []types.ScanResultReader{reader}); err != nil {
				t.Fatalf("Error writing CSV: %v", err)
			}
			csvOutput := buf.String()
			if csvOutput == "" {
				t.Fatalf("Expected non-empty CSV, got empty")
			}
		})
	}
}

func checkError(t *testing.T, err error, expectError bool) {
	t.Helper()
	if expectError {
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	} else {
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}
}
