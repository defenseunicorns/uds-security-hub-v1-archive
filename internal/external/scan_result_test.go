package external

import (
	"encoding/json"
	"os"
	"testing"
)

// TestScanResultDeserialization tests the ScanResultDeserialization function.
func TestScanResultDeserialization(t *testing.T) {
	// Load the JSON data from the file
	data, err := os.ReadFile("testdata/scanresult.json")
	if err != nil {
		t.Fatalf("Failed to read JSON file: %s", err)
	}

	// Deserialize the JSON data into the ScanResult struct
	var result ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to deserialize JSON data: %s", err)
	}

	// Perform checks to ensure the data is deserialized correctly
	if result.SchemaVersion == 0 {
		t.Errorf("Expected SchemaVersion to be set")
	}
	if result.CreatedAt.IsZero() {
		t.Errorf("Expected CreatedAt to be a valid time")
	}
	if result.ArtifactName == "" {
		t.Errorf("Expected ArtifactName to be non-empty")
	}
	if len(result.Results) == 0 {
		t.Errorf("Expected Results to contain elements")
	}

	// Check a few fields deeply
	if len(result.Results[0].Vulnerabilities) == 0 {
		t.Errorf("Expected Vulnerabilities to contain elements")
	}
	vuln := result.Results[0].Vulnerabilities[0]
	if vuln.VulnerabilityID == "" {
		t.Errorf("Expected VulnerabilityID to be non-empty")
	}
	if vuln.PkgName == "" {
		t.Errorf("Expected PkgName to be non-empty")
	}
	if vuln.Severity == "" {
		t.Errorf("Expected Severity to be non-empty")
	}
	if vuln.PublishedDate.IsZero() {
		t.Errorf("Expected PublishedDate to be a valid time")
	}
	if vuln.LastModifiedDate.IsZero() {
		t.Errorf("Expected LastModifiedDate to be a valid time")
	}
}
