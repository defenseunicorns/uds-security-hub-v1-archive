package scan

import (
	"os"
	"strings"
	"testing"
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
			if (err != nil) != tc.wantErr {
				t.Errorf("got error %v, want error %v", err != nil, tc.wantErr)
			}
		})
	}
}

func TestUnmarshalJSONFromFilename(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	validYAML := "key: value"
	tmpFile.WriteString(validYAML)
	tmpFile.Close()

	var output map[string]string
	err = unmarshalJSONFromFilename(tmpFile.Name(), &output)
	if err != nil || output["key"] != "value" {
		t.Errorf("failed to unmarshal valid YAML, got: %v", err)
	}

	invalidFile := "nonexistent.yaml"
	err = unmarshalJSONFromFilename(invalidFile, &output)
	if err == nil {
		t.Errorf("expected error for nonexistent file, got none")
	}
}

func TestUnmarshalJSONFromFilename_DecodeError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "invalid*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("invalid_yaml: [unterminated")
	if err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	var output map[string]interface{}
	err = unmarshalJSONFromFilename(tmpFile.Name(), &output)
	if err == nil || !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("expected decode error, got: %v", err)
	}
}

func TestExtractRootFsFromTarFilePath(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"

	tmpDir, err := os.MkdirTemp("", "extract-rootfs-*")
	if err != nil {
		t.Fatalf("failed to create tmpdir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	refs, err := ExtractRootFsFromTarFilePath(tmpDir, filePath)
	if err != nil {
		t.Fatalf("Failed to extract images from tar: %v", err)
	}

	if len(refs) != 1 {
		t.Errorf("did not extract correct number of refs; want %d, got %d", 1, len(refs))
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
