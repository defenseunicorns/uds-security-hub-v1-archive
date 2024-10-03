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
			diff := cmp.Diff(tt.expected, scanner, cmp.AllowUnexported(LocalPackageScanner{}), cmpopts.IgnoreUnexported(slog.Logger{}))
			require.Empty(t, diff, "scanner mismatch (-expected +got):\n%s", diff)
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
			require.NoError(t, err, "failed to create local package scanner")
			result, err := lps.Scan(ctx)
			require.NoError(t, err, "failed to scan image")
			reader, err := lps.ScanResultReader(result.Results[0])
			require.NoError(t, err, "failed to get scan result reader")
			artifactName := reader.GetArtifactName()
			require.NotEmpty(t, artifactName, "expected artifact name to be non-empty, got empty")
			vulnerabilities := reader.GetVulnerabilities()
			require.NotEmpty(t, vulnerabilities, "expected vulnerabilities to be non-empty, got empty")
			var buf bytes.Buffer
			require.NoError(t, WriteToJSON(&buf, []types.ScanResultReader{reader}), "error writing json")
			jsonOutput := buf.String()
			require.NotEmpty(t, jsonOutput, "expected JSON to be non-empty, got empty")
			buf.Reset() // Reset buffer for CSV writing
			require.NoError(t, WriteToCSV(&buf, []types.ScanResultReader{reader}), "error writing csv")
			csvOutput := buf.String()
			require.NotEmpty(t, csvOutput, "expected csv to be non-empty, got empty")
		})
	}
}

func checkError(t *testing.T, err error, expectError bool) {
	t.Helper()
	if expectError {
		if err == nil {
			require.Error(t, err, "expected an error, but got none")
		}
	} else {
		if err != nil {
			require.NoError(t, err, "expected no error, but got one")
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
	require.Error(t, err, "expected error for empty packagePath, got :%v", err)
	require.ErrorContains(t, err, "packagePath cannot be empty", "unexpected error message")
}

func TestExtractFilesFromTar(t *testing.T) {
	data := []byte("mock data")
	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "testfile.txt", Size: int64(len(data))}), "error writing tar header")

	_, err := tw.Write(data)
	require.NoError(t, err, "error writing data to tar")

	require.NoError(t, tw.Close(), "failed to close writer")

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
			diff := cmp.Diff(tt.wantResult, results)
			require.Empty(t, diff, "results mismatch (-want +got):\n%s", diff)
		})
	}
}
