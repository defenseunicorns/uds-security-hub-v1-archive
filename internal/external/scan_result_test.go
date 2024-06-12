//go:build integration
// +build integration

package external

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
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

func TestMapScanResultToDTO(t *testing.T) {
	// Prepare test data
	metadata := model.Metadata{
		RepoTags:    []string{"test-repo-tag"},
		RepoDigests: []string{"test-repo-digest"},
		ImageConfig: model.ImageConfig{
			Architecture: "test-architecture",
			OS:           "test-os",
		},
		DiffIDs: []string{"test-diff-id"},
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %s", err)
	}
	vulnerabilities := []model.Vulnerability{
		{
			PkgName: "test-pkg-name",
		},
	}
	createdAt := time.Now()

	scanResult := &ScanResult{
		Metadata:     metadata,
		CreatedAt:    createdAt,
		ArtifactName: "test-artifact",
		ArtifactType: "test-type",
		Results: []struct {
			Target          string                `json:"Target"`
			Class           string                `json:"Class"`
			Type            string                `json:"Type"`
			Vulnerabilities []model.Vulnerability `json:"Vulnerabilities"`
		}{
			{
				Target:          "test-target",
				Class:           "test-class",
				Type:            "test-type",
				Vulnerabilities: vulnerabilities,
			},
		},
		SchemaVersion: 1,
		ID:            123,
	}

	expectedDTOs := []ScanDTO{
		{
			ID:              123,
			SchemaVersion:   1,
			CreatedAt:       createdAt,
			ArtifactName:    "test-artifact",
			ArtifactType:    "test-type",
			Metadata:        json.RawMessage(metadataJSON),
			Vulnerabilities: vulnerabilities,
		},
	}

	// Call the function
	actualDTOs := MapScanResultToDTO(scanResult)

	cmp.Diff(expectedDTOs, actualDTOs, cmpopts.IgnoreFields(model.Scan{}, "CreatedAt", "UpdatedAt"))
}

func TestMapPackageToDTO(t *testing.T) {
	// Prepare test data

	vulnerabilities := []model.Vulnerability{
		{
			PkgName: "test-pkg-name",
		},
	}
	createdAt := time.Now()
	updatedAt := time.Now()

	scan := model.Scan{
		ID:              123,
		SchemaVersion:   1,
		CreatedAt:       createdAt,
		ArtifactName:    "test-artifact",
		ArtifactType:    "test-type",
		Vulnerabilities: vulnerabilities,
	}

	pkg := &model.Package{
		ID:         456,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		Name:       "test-package",
		Repository: "test-repo",
		Tag:        "test-tag",
		Scans:      []model.Scan{scan},
	}

	expectedDTO := PackageDTO{
		ID:         456,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		Name:       "test-package",
		Repository: "test-repo",
		Tag:        "test-tag",
		Scans: []ScanDTO{
			{
				ID:              123,
				SchemaVersion:   1,
				CreatedAt:       createdAt,
				ArtifactName:    "test-artifact",
				ArtifactType:    "test-type",
				Vulnerabilities: vulnerabilities,
			},
		},
	}

	// Call the function
	actualDTO := MapPackageToDTO(pkg)

	// Compare the expected and actual DTOs
	if diff := cmp.Diff(expectedDTO, actualDTO, cmpopts.IgnoreFields(model.Scan{}, "CreatedAt", "UpdatedAt")); diff != "" {
		t.Errorf("MapPackageToDTO() mismatch (-want +got):\n%s", diff)
	}
}
