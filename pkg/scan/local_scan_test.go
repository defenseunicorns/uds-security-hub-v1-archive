package scan

import (
	"testing"
)

func TestFetchImageE2E(t *testing.T) {
	filePath := "testdata/zarf-package-mattermost-arm64-9.9.1-uds.0.tar.zst"

	images, err := ExtractImagesFromTar(filePath)
	if err != nil {
		t.Fatalf("Failed to extract images from tar: %v", err)
	}

	if len(images) == 0 {
		t.Fatal("Expected non-empty images, got empty")
	}

	expectedImages := []string{
		"docker.io/mattermost/mattermost-enterprise-edition:9.9.1",
		"docker.io/appropriate/curl:latest",
	}

	for _, expectedImage := range expectedImages {
		found := false
		for _, image := range images {
			if image == expectedImage {
				found = true
				t.Logf("Found expected image: %s", image)
				break
			}
		}
		if !found {
			t.Errorf("Expected image not found: %s", expectedImage)
		}
	}

	// Optional: Log all found images
	for _, image := range images {
		t.Logf("Image: %s", image)
	}

	// Remove this line as it's causing the test to always fail
	// t.Fatalf("Expected 1 tag, got %d", 10)
}
