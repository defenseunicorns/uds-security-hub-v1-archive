//go:build integration
// +build integration

package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestScanModel tests the Scan model.
func TestScanModel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Auto-migrate the Scan model
	err = db.AutoMigrate(&Scan{})
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
			},
		},
	}

	for _, tc := range testCases {
		// Save the Scan to the database
		result := db.Create(tc.scan)
		if result.Error != nil {
			t.Fatalf("failed to save Scan: %v", result.Error)
		}

		// Retrieve the saved Scan from the database
		var retrievedScan Scan
		result = db.First(&retrievedScan, "id = ?", tc.scan.ID)
		if result.Error != nil {
			t.Fatalf("failed to retrieve Scan: %v", result.Error)
		}

		// Compare the retrieved Scan with the original instance using cmp
		if diff := cmp.Diff(tc.scan, &retrievedScan, cmpopts.IgnoreFields(Scan{}, "CreatedAt", "UpdatedAt")); diff != "" {
			t.Errorf("retrieved Scan differs: (-want +got)\n%s", diff)
		}
	}

	// Clean up the test database
	_ = db.Migrator().DropTable(&Scan{}) //nolint:errcheck
}
