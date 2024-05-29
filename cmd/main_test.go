package main

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/pkg/scan"
)

func TestE2EScanFunctionality(t *testing.T) {
	// Set up the context and logger
	ctx := context.Background()
	logger := log.NewLogger(ctx)

	// Define the test inputs
	trivyUsername := "testuser"
	trivyPassword := "testpass"
	ghcrToken := "testtoken"
	org := "defenseunicorns"
	packageName := "packages/uds/mattermost"
	tag := "9.8.0-uds.0-upstream"

	// Create the scanner
	scanner, err := scan.New(ctx, logger, trivyUsername, trivyPassword, ghcrToken)
	if err != nil {
		t.Fatalf("Error creating scanner: %v", err)
	}

	// Perform the scan
	results, err := scanner.ScanZarfPackage(org, packageName, tag)
	if err != nil {
		t.Fatalf("Error scanning package: %v", err)
	}

	// Process the results
	var combinedCSV string
	for i, v := range results {
		r, err := scanner.ScanResultReader(v)
		if err != nil {
			t.Fatalf("Error reading scan result: %v", err)
		}

		csv := r.GetResultsAsCSV()
		if i == 0 {
			combinedCSV = csv
		} else {
			combinedCSV += "\n" + csv[strings.Index(csv, "\n")+1:]
		}
	}

	// Verify the combined CSV output
	if len(combinedCSV) == 0 {
		t.Fatalf("Combined CSV output is empty")
	}
}
