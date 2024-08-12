package scan

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
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
		name        string
		logger      types.Logger
		packagePath string
		expected    *LocalPackageScanner
		expectError bool
	}{
		{
			name:        "valid inputs",
			logger:      logger,
			packagePath: packagePath,
			expected: &LocalPackageScanner{
				logger:      logger,
				packagePath: packagePath,
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
			scanner, err := NewLocalPackageScanner(tt.logger, tt.packagePath, "")
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

	lps, err := NewLocalPackageScanner(logger, zarfPackagePath, "")
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
	if err := reader.WriteToCSV(&buf, true); err != nil {
		t.Fatalf("Error writing csv: %v", err)
	}
	csv := buf.String()
	if csv == "" {
		t.Fatalf("Expected non-empty CSV, got empty")
	}
}

func TestReplacePathChars(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "ghcr.io/stefanprodan/podinfo:6.4.0",
			expected: "ghcr.io-stefanprodan-podinfo_6.4.0",
		},
		{
			input:    "ghcr.io/argoproj/argocd:v2.9.6",
			expected: "ghcr.io-argoproj-argocd_v2.9.6",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			result := replacePathChars(testCase.input)
			if result != testCase.expected {
				t.Errorf("unexpected output; got %s, want %s", result, testCase.expected)
			}
		})
	}
}

func TestScannableImage(t *testing.T) {
	testCases := []struct {
		imageName string
		expected  bool
	}{
		{
			imageName: "quay.io/argoproj/argocd:v2.9.6",
			expected:  true,
		},
		{
			imageName: "quay.io/argoproj/argocd:sha256-2dafd800fb617ba5b16ae429e388ca140f66f88171463d23d158b372bb2fae08.att",
			expected:  false,
		},
		{
			imageName: "quay.io/argoproj/argocd:sha256-2dafd800fb617ba5b16ae429e388ca140f66f88171463d23d158b372bb2fae08.sig",
			expected:  false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.imageName, func(t *testing.T) {
			result := scannableImage(testCase.imageName)
			if result != testCase.expected {
				t.Errorf("unexpected output; got %v, want %v", result, testCase.expected)
			}
		})
	}
}

func TestExtractRootFS(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"
	refs, err := ExtractRootFS(filePath, executor.NewCommandExecutor(context.TODO()))
	if err != nil {
		t.Fatalf("Failed to extract images from tar: %v", err)
	}

	if len(refs.Refs) != 1 {
		t.Errorf("did not extract correct number of refs; want %d, got %d", 1, len(refs.Refs))
	}

	if err := refs.Close(); err != nil {
		t.Errorf("unable to clean up results after use: %s", err)
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

	expectedImageNameFromSBOM := []string{
		"docker.io/appropriate/curl:latest",
	}

	for _, sbomName := range expectedImageNameFromSBOM {
		found := false
		for _, ref := range refs {
			if ref.ArtifactName == sbomName {
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
