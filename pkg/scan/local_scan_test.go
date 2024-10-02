package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestNewLocalPackageScanner(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	packagePath := "/path/to/package"

	tests := []struct {
		logger      *slog.Logger
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
			if diff := cmp.Diff(tt.expected, scanner, cmp.AllowUnexported(LocalPackageScanner{}), cmpopts.IgnoreUnexported(slog.Logger{})); diff != "" {
				t.Errorf("scanner mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestScanImageE2E(t *testing.T) {
	const zarfPackagePath = "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

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
			reader, err := lps.ScanResultReader(result.Results[0])
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

func TestLocalPackageScanner_Scan_LPSEmptyPackagePath(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	lps := &LocalPackageScanner{
		logger:      logger,
		packagePath: "",
		scannerType: SBOMScannerType,
	}

	_, err := lps.Scan(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "packagePath cannot be empty")
}

func TestLocalPackageScanner_ScanResultReader_OpenJSONError(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	scanner := &LocalPackageScanner{
		logger:      logger,
		packagePath: "mock-package-path.tar.zst",
	}

	result := types.PackageScannerResult{
		JSONFilePath: "non-existent-file.json",
	}

	_, err := scanner.ScanResultReader(result)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to open JSON file")
	require.ErrorContains(t, err, "no such file or directory")
}

func TestLocalPackageScanner_ScanResultReader_DecodeJSONError(t *testing.T) {
	file, err := os.CreateTemp("", "invalid-json-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	if _, err := file.Write([]byte("invalid json content")); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	scanner := &LocalPackageScanner{
		logger:      logger,
		packagePath: "mock-package-path.tar.zst",
	}

	result := types.PackageScannerResult{
		JSONFilePath: file.Name(),
	}

	_, err = scanner.ScanResultReader(result)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to decode JSON file")
	require.ErrorContains(t, err, "invalid character 'i' looking for beginning of value")
}

func TestExtractFilesFromTar(t *testing.T) {
	data := []byte("mock data")
	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	if err := tw.WriteHeader(&tar.Header{Name: "testfile.txt", Size: int64(len(data))}); err != nil {
		t.Fatalf("Error writing tar header: %v", err)
	}

	if _, err := tw.Write(data); err != nil {
		t.Fatalf("Error writing data to tar: %v", err)
	}
	tw.Close()

	tests := []struct {
		name       string
		reader     io.Reader
		filenames  []string
		wantResult map[string][]byte
		expectErr  bool
	}{
		{
			name:      "valid extraction",
			reader:    bytes.NewReader(buf.Bytes()),
			filenames: []string{"testfile.txt"},
			wantResult: map[string][]byte{
				"testfile.txt": data,
			},
			expectErr: false,
		},
		{
			name:       "missing file",
			reader:     bytes.NewReader(buf.Bytes()),
			filenames:  []string{"missing.txt"},
			wantResult: map[string][]byte{},
			expectErr:  false,
		},
		{
			name:      "corrupted tar file",
			reader:    bytes.NewReader([]byte("not a tar file")),
			filenames: []string{"testfile.txt"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := extractFilesFromTar(tt.reader, tt.filenames...)
			checkError(t, err, tt.expectErr)
			if diff := cmp.Diff(tt.wantResult, results); diff != "" {
				t.Errorf("results mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
