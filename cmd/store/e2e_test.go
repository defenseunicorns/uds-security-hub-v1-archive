package main

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

// TestStore is a test for the store command e2e.
func TestStore(t *testing.T) {
	if os.Getenv("integration") != "true" {
		t.Skip("Skipping integration test")
	}
	tmp, err := os.MkdirTemp("", "uds-security-hub-db-conn-*")
	if err != nil {
		t.Fatalf("failed to create tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	testDBPath := path.Join(tmp, "uds_security_hub.db")

	github := os.Getenv("GITHUB_TOKEN")
	ghcrCreds := os.Getenv("GHCR_CREDS")
	if github == "" || ghcrCreds == "" {
		t.Fatalf("GITHUB_TOKEN and GHCR_CREDS are required")
	}

	startTime := time.Now()

	os.Args = []string{
		"program",
		"--registry-creds", ghcrCreds,
		"-n", "packages/uds/mattermost",
		"--db-path", testDBPath,
		"-v", "1",
		"-t", github,
	}

	initializer := DefaultDatabaseInitializer
	db, err := initializer.Initialize(&sql.DatabaseConfig{DBType: "sqlite", DBPath: testDBPath})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if the connection is valid
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	main()

	// check the scans for ArtifactName and correct count
	var scans []model.Scan
	if result := db.Where("created_at > ?", startTime).Find(&scans); result.Error != nil {
		t.Fatalf("failed to find scans, got %v", result.Error)
	}

	if len(scans) != 2 {
		t.Fatalf("Expected 2 rows in scan table, got %d", len(scans))
	}

	var count int64
	row := db.Model(&model.Package{}).Count(&count)
	if err := row.Error; err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if count <= 0 {
		t.Fatalf("Expected more than 0 row in package table, got %d", count)
	}
	t.Logf("Package %d rows", count)

	// Check the number of rows in the report table as there should be a report created.
	row = db.Model(&model.Report{}).Count(&count)
	if err := row.Error; err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if count <= 0 {
		t.Fatalf("Expected more than 0 row in report table, got %d", count)
	}
	t.Logf("Report %d rows", count)
}
