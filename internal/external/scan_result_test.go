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
				Target: "/some/long/filename",
				Class:  "os-pkg",
				Type:   "chainguard",
				Vulnerabilities: []model.Vulnerability{
					{
						PkgName: "os-pkg-result-1",
					},
					{
						PkgName: "os-pkg-result-2",
					},
				},
			},
			{
				Target: "NodeJS",
				Class:  "lang-pkgs",
				Type:   "node-pkg",
				Vulnerabilities: []model.Vulnerability{
					{
						PkgName: "lang-pkg-result-1",
					},
					{
						PkgName: "lang-pkg-result-2",
					},
				}},
		},
		SchemaVersion: 1,
		ID:            123,
	}

	expectedDTO := ScanDTO{
		ID:            123,
		SchemaVersion: 1,
		CreatedAt:     createdAt,
		ArtifactName:  "test-artifact",
		ArtifactType:  "test-type",
		Metadata:      json.RawMessage(metadataJSON),
		Vulnerabilities: []model.Vulnerability{
			{
				Target:  "/some/long/filename",
				Class:   "os-pkg",
				Type:    "chainguard",
				PkgName: "os-pkg-result-1",
			},
			{
				Target:  "/some/long/filename",
				Class:   "os-pkg",
				Type:    "chainguard",
				PkgName: "os-pkg-result-2",
			},
			{
				Target:  "NodeJS",
				Class:   "lang-pkgs",
				Type:    "node-pkg",
				PkgName: "lang-pkg-result-1",
			},
			{
				Target:  "NodeJS",
				Class:   "lang-pkgs",
				Type:    "node-pkg",
				PkgName: "lang-pkg-result-2",
			},
		},
	}

	// Call the function
	actualDTOs := MapScanResultToDTO(scanResult)

	// Compare the expected and actual DTOs
	if diff := cmp.Diff(expectedDTO, actualDTOs); diff != "" {
		t.Errorf("MapScanResultToDTO() mismatch (-want +got):\n%s", diff)
	}
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

func TestMapPackageDTOToReport(t *testing.T) {
	tests := []struct {
		name     string
		dto      *PackageDTO
		sbom     []byte
		expected *model.Report
	}{
		{
			name: "Basic test",
			dto: &PackageDTO{
				CreatedAt: time.Now(),
				Name:      "test-package",
				Tag:       "v1.0.0",
				Scans: []ScanDTO{
					{
						Vulnerabilities: []model.Vulnerability{
							{Severity: "CRITICAL"},
							{Severity: "HIGH"},
						},
					},
				},
			},
			sbom: []byte("test-sbom"),
			expected: &model.Report{
				PackageName: "test-package",
				Tag:         "v1.0.0",
				SBOM:        []byte("test-sbom"),
				Critical:    1,
				High:        1,
				Medium:      0,
				Low:         0,
				Info:        0,
				Total:       2,
			},
		},
		{
			name: "No vulnerabilities",
			dto: &PackageDTO{
				CreatedAt: time.Now(),
				Name:      "test-package",
				Tag:       "v1.0.0",
				Scans: []ScanDTO{
					{
						Vulnerabilities: []model.Vulnerability{},
					},
				},
			},
			sbom: []byte("test-sbom"),
			expected: &model.Report{
				PackageName: "test-package",
				Tag:         "v1.0.0",
				SBOM:        []byte("test-sbom"),
				Critical:    0,
				High:        0,
				Medium:      0,
				Low:         0,
				Info:        0,
				Total:       0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := MapPackageDTOToReport(tt.dto, tt.sbom)
			if diff := cmp.Diff(tt.expected, report, cmpopts.IgnoreFields(model.Report{}, "CreatedAt")); diff != "" {
				t.Errorf("MapPackageDTOToReport() mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestCountVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		scans    []ScanDTO
		severity string
		expected int
	}{
		{
			name: "Count Critical",
			scans: []ScanDTO{
				{
					Vulnerabilities: []model.Vulnerability{
						{Severity: "Critical"},
						{Severity: "High"},
					},
				},
			},
			severity: "Critical",
			expected: 1,
		},
		{
			name: "Count High",
			scans: []ScanDTO{
				{
					Vulnerabilities: []model.Vulnerability{
						{Severity: "Critical"},
						{Severity: "High"},
					},
				},
			},
			severity: "High",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := countVulnerabilities(tt.scans, tt.severity)
			if diff := cmp.Diff(tt.expected, count); diff != "" {
				t.Errorf("countVulnerabilities() mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
