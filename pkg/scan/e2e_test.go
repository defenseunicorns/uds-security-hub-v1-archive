package scan

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-security-hub/internal/docker"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
)

func TestE2EScanFunctionality(t *testing.T) {
	if os.Getenv("integration") != "true" {
		t.Skip("Skipping integration test")
	}
	// Set up the context and logger
	ctx := context.Background()
	logger := log.NewLogger(ctx)
	ghcrCreds := os.Getenv("GHCR_CREDS")
	registry1Creds := os.Getenv("REGISTRY1_CREDS")
	dockerCreds := os.Getenv("DOCKER_IO_CREDS")
	if ghcrCreds == "" || registry1Creds == "" || dockerCreds == "" {
		t.Fatalf("GHCR_CREDS and REGISTRY1_CREDS must be set")
	}
	registryCreds := docker.ParseCredentials([]string{ghcrCreds, registry1Creds, dockerCreds})
	// Define the test inputs

	org := "defenseunicorns"
	packageName := "packages/uds/sonarqube"
	tag := "9.9.5-uds.1-upstream"
	dockerConfigPath, err := docker.GenerateAndWriteDockerConfig(ctx, registryCreds)
	if err != nil {
		t.Fatalf("Error generating and writing Docker config: %v", err)
	}
	// Create the scanner
	scanner := NewRemotePackageScanner(ctx, logger, dockerConfigPath, org, packageName, tag, "")
	if err != nil {
		t.Fatalf("Error creating scanner: %v", err)
	}
	rps, ok := scanner.(*Scanner)
	if !ok {
		t.Fatalf("Error creating scanner: %v", err)
	}
	// Perform the scan
	results, err := rps.ScanZarfPackage(org, packageName, tag)
	if err != nil {
		t.Fatalf("Error scanning package: %v", err)
	}

	// Process the results
	var buf bytes.Buffer
	for i, v := range results {
		r, err := scanner.ScanResultReader(v)
		if err != nil {
			t.Fatalf("Error reading scan result: %v", err)
		}

		r.WriteToCSV(&buf, i == 0)
	}

	combinedCSV := buf.String()

	// Verify the combined CSV output
	if len(combinedCSV) == 0 {
		t.Fatalf("Combined CSV output is empty")
	}

	// make sure the header only exists in the first line
	lines := strings.Split(combinedCSV, "\n")
	if slices.Contains(lines[1:], lines[0]) {
		t.Error("the header line appears more than once")
	}
}
