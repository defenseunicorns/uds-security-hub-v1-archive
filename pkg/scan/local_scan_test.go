package scan

import (
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
	dockerConfigPath := "/path/to/docker/config"
	packagePath := "/path/to/package"

	tests := []struct {
		name         string
		logger       types.Logger
		dockerConfig string
		packagePath  string
		expected     *LocalPackageScanner
		expectError  bool
	}{
		{
			name:         "valid inputs",
			logger:       logger,
			dockerConfig: dockerConfigPath,
			packagePath:  packagePath,
			expected: &LocalPackageScanner{
				logger:           logger,
				dockerConfigPath: dockerConfigPath,
				packagePath:      packagePath,
			},
			expectError: false,
		},
		{
			name:         "empty packagePath",
			logger:       logger,
			dockerConfig: dockerConfigPath,
			packagePath:  "",
			expected:     nil,
			expectError:  true,
		},
		{
			name:         "nil logger",
			logger:       nil,
			dockerConfig: dockerConfigPath,
			packagePath:  packagePath,
			expected:     nil,
			expectError:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewLocalPackageScanner(tt.logger, tt.dockerConfig, tt.packagePath, "")
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

	lps, err := NewLocalPackageScanner(logger, "", zarfPackagePath, "")
	if err != nil {
		t.Fatalf("Failed to create local package scanner: %v", err)
	}
	result, err := lps.Scan(ctx)
	if err != nil {
		t.Fatalf("Failed to scan image: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 results, got %d", len(result))
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
	csv := reader.GetResultsAsCSV()
	if csv == "" {
		t.Fatalf("Expected non-empty CSV, got empty")
	}
}

func TestExtractSBOMsFromTar(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"
	refs, err := ExtractSBOMsFromTar(filePath)
	if err != nil {
		t.Fatalf("Failed to extract images from tar: %v", err)
	}

	if len(refs) == 0 {
		t.Fatal("Expected non-empty images, got empty")
	}

	expectedSBOMS := []string{
		"docker.io_appropriate_curl_latest.json",
	}

	for _, sbomName := range expectedSBOMS {
		found := false
		for _, ref := range refs {
			if ref.Name == sbomName {
				found = true
				t.Logf("Found expected image: %s", sbomName)

				if ref.SBOMFile == "" {
					t.Error("got an empty sbomfile, this will not be scannable by trivy")
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected image not found: %s", sbomName)
		}
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
