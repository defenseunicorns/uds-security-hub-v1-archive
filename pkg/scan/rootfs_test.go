package scan

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeArchivePath(t *testing.T) {
	testCases := []struct {
		dir      string
		filename string
		wantErr  bool
	}{
		{"/safe/dir", "file.txt", false},                  // valid path
		{"/safe/dir", "../unsafe.txt", true},              // directory traversal attempt
		{"/safe/dir", "/safe/dir/subdir/file.txt", false}, // nested safe path
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			_, err := sanitizeArchivePath(tc.dir, tc.filename)
			if tc.wantErr {
				require.Error(t, err, "expected error but got none")
			} else {
				require.NoError(t, err, "got an unexpected error")
			}
		})
	}
}

func TestUnmarshalJSONFromFilename(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test.yaml")
	require.NoError(t, err, "failed to create temp file: %v", err)
	defer os.Remove(tmpFile.Name())

	validYAML := "key: value"
	_, err = tmpFile.WriteString(validYAML)
	require.NoError(t, err, "failed to write to temp file")

	require.NoError(t, tmpFile.Close(), "failed to close temp file")

	var output map[string]string
	err = unmarshalJSONFromFilename(tmpFile.Name(), &output)
	require.NoError(t, err, "failed to unmarshal valid YAML")
	require.Equal(t, "value", output["key"], "unexpected value for 'key'")

	invalidFile := "nonexistent.yaml"
	err = unmarshalJSONFromFilename(invalidFile, &output)
	require.Error(t, err, "expected error for nonexistent file, but got none")
}

func TestUnmarshalJSONFromFilename_DecodeError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "invalid*.yaml")
	require.NoError(t, err, "failed to create temp file: %v", err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("invalid_yaml: [unterminated")
	require.NoError(t, err, "failed to write to temp file: %v", err)
	tmpFile.Close()

	var output map[string]interface{}
	err = unmarshalJSONFromFilename(tmpFile.Name(), &output)
	require.Error(t, err, "expected decode error, but got none")
	require.ErrorContains(t, err, "failed to decode")
}

func TestExtractRootFsFromTarFilePath(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"

	tmpDir, err := os.MkdirTemp("", "extract-rootfs-*")
	require.NoError(t, err, "failed to create tmpdir: %s", err)
	defer os.RemoveAll(tmpDir)

	refs, err := ExtractRootFsFromTarFilePath(tmpDir, filePath)
	require.NoError(t, err, "failed to extract images from tar: %v", err)

	require.Len(t, refs, 1, "did not extract number of refs; want %d, got %d", 1, len(refs))
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
			require.Equal(t, testCase.expected, result, "unexpected output")
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
			require.Equal(t, testCase.expected, result, "unexpected output")
		})
	}
}
