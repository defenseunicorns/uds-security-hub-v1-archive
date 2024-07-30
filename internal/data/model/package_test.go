package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestPackageModel tests the Package model.
func TestPackageModel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Auto-migrate the models
	err = db.AutoMigrate(&Package{}, &Scan{}, &Vulnerability{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	// Test cases for different Package instances
	testCases := []struct {
		pkg *Package
	}{
		{
			pkg: &Package{
				Name:       "example-package",
				Repository: "example-repo",
				Tag:        "v1.0.0",
				Scans: []Scan{
					{
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
				ID:        1,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
	}

	for _, tc := range testCases {
		// Save the Package to the database
		result := db.Create(tc.pkg)
		if result.Error != nil {
			t.Fatalf("failed to save Package: %v", result.Error)
		}

		// Retrieve the saved Package from the database with preloaded Scans and Vulnerabilities
		var retrievedPackage Package
		result = db.Preload("Scans").Preload("Scans.Vulnerabilities").First(&retrievedPackage, "id = ?", tc.pkg.ID)
		if result.Error != nil {
			t.Fatalf("failed to retrieve Package: %v", result.Error)
		}

		// Compare the retrieved Package with the original instance using cmp
		if diff := cmp.Diff(tc.pkg, &retrievedPackage); diff != "" {
			t.Errorf("retrieved Package differs: (-want +got)\n%s", diff)
		}
	}
	// Clean up the test database
	_ = db.Migrator().DropTable(&Package{}, &Scan{}, &Vulnerability{}) //nolint:errcheck
}
