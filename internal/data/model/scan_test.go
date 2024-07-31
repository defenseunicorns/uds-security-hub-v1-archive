package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestScanModel tests the Scan model.
func TestScanModel(t *testing.T) {
	const vulnerabilities = "Vulnerabilities"
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Auto-migrate the Scan model
	err = db.AutoMigrate(&Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate Scan model: %v", err)
	}

	// Test cases for different Scan instances
	testCases := []struct {
		scan *Scan
	}{
		{
			scan: &Scan{
				SchemaVersion: 1,
				ArtifactName:  "example-image",
				ArtifactType:  "container",
				Metadata:      json.RawMessage(`{"ImageConfig": {"Architecture": "amd64", "OS": "linux"}}`),
				Entrypoint:    json.RawMessage(`["/bin/bash"]`),
				Vulnerabilities: []Vulnerability{
					{
						Title:            "Example Vulnerability",
						Severity:         "HIGH",
						CweIDs:           CweIDs{"CWE-79"},
						References:       []string{"a", "b"},
						CVSS:             CVSS{"example": CVSSData{V3Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8}},
						CreatedAt:        time.Now(),
						LastModifiedDate: time.Now(),
						PublishedDate:    time.Now(),
						UpdatedAt:        time.Now(),
						VendorSeverity:   VendorSeverity{"example": 5},
						DataSource:       DataSource{ID: "example-id", Name: "example-name", URL: "http://example.com"},
						Layer:            Layer{Digest: "example-digest", DiffID: "example-diffid"},
						PkgIdentifier:    PkgIdentifier{PURL: "pkg:example", UID: "example-uid"},
						Description:      "Example description",
						FixedVersion:     "1.0.1",
						InstalledVersion: "1.0.0",
						PkgName:          "example-package",
						PkgPath:          "/usr/local/example",
						PrimaryURL:       "http://example.com/vuln",
						SeveritySource:   "example-source",
						Status:           "fixed",
						Target:           "example-target",
						Class:            "example-class",
						Type:             "example-type",
						ScanID:           1,
						ID:               1,
					},
				},
				ID:        1,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PackageID: 1,
			},
		},
		{
			scan: &Scan{
				SchemaVersion: 1,
				ArtifactName:  "example-image",
				ArtifactType:  "container",
				Metadata:      json.RawMessage(`{"ImageConfig": {"Architecture": "amd64", "OS": "linux"}}`),
				Entrypoint:    json.RawMessage(`["/bin/bash"]`),
				Vulnerabilities: []Vulnerability{
					{
						Title:      "Example Vulnerability",
						Severity:   "HIGH",
						CweIDs:     CweIDs{"CWE-79"},
						References: []string{"a", "b"},
						ScanID:     2,
						ID:         3,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		// Save the Scan to the database
		result := db.Create(tc.scan)
		if result.Error != nil {
			t.Fatalf("failed to save Scan: %v", result.Error)
		}

		// Retrieve the saved Scan from the database with preloaded Vulnerabilities
		var retrievedScan Scan
		result = db.Preload(vulnerabilities).First(&retrievedScan, "id = ?", tc.scan.ID)
		if result.Error != nil {
			t.Fatalf("failed to retrieve Scan: %v", result.Error)
		}
		// Compare the retrieved Scan with the original instance using cmp
		if diff := cmp.Diff(tc.scan, &retrievedScan); diff != "" {
			t.Errorf("retrieved Scan differs: (-want +got)\n%s", diff)
		}
	}

	// Clean up the test database
	_ = db.Migrator().DropTable(&Scan{}) //nolint:errcheck
}
