package scan

import (
	"testing"
)

func TestExtractRootFsFromTarFilePath(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"

	refs, cleanup, err := ExtractRootFsFromTarFilePath(filePath)
	if err != nil {
		t.Fatalf("Failed to extract images from tar: %v", err)
	}
	defer cleanup()

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
