package scan

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/internal/docker"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestE2EScanFunctionality(t *testing.T) {
	if os.Getenv("integration") != "true" {
		t.Skip("Skipping integration test")
	}
	testCases := []struct {
		name        string
		scannerType ScannerType
	}{
		{name: "SBOM Scanner", scannerType: SBOMScannerType},
		{name: "RootFS Scanner", scannerType: RootFSScannerType},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the context and logger
			ctx := context.Background()
			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			ghcrCreds := os.Getenv("GHCR_CREDS")
			require.NotEmpty(t, ghcrCreds, "GHCR_CREDS must be set")
			registryCreds := docker.ParseCredentials([]string{ghcrCreds})
			// Define the test inputs

			org := "defenseunicorns"
			packageName := "packages/uds/sonarqube"
			tag := "9.9.5-uds.1-upstream"
			// Create the scanner
			scanner := NewRemotePackageScanner(ctx, logger, org, packageName, tag, "", registryCreds, tt.scannerType)
			// Perform the scan
			scan, err := scanner.Scan(ctx)
			require.NoError(t, err, "error scanning package")

			var allResults []types.ScanResultReader

			for _, v := range scan.Results {
				r, err := scanner.ScanResultReader(v)
				require.NoError(t, err, "error reading scan result")

				allResults = append(allResults, r)
			}

			// Process the results
			var buf bytes.Buffer
			require.NoError(t, WriteToCSV(&buf, allResults), "failed to WriteToCSV")
			combinedCSV := buf.String()

			// Verify the combined CSV output
			require.NotEmpty(t, combinedCSV, "combined csv output is empty")

			// make sure the header only exists in the first line
			lines := strings.Split(combinedCSV, "\n")
			require.False(t, slices.Contains(lines[1:], lines[0]), "the header line appears more than once")
		})
	}
}
