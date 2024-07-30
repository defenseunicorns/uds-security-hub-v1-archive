package main

import (
	"os"
	"testing"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

// TestStore is a test for the store command e2e.
func TestStore(t *testing.T) {
	if os.Getenv("integration") != "true" {
		t.Skip("Skipping integration test")
	}
	const testDBPath = "tests/uds_security_hub.db"
	github := os.Getenv("GITHUB_TOKEN")
	ghcrCreds := os.Getenv("GHCR_CREDS")
	registry1Creds := os.Getenv("REGISTRY1_CREDS")
	dockerCreds := os.Getenv("DOCKER_IO_CREDS")
	if github == "" || ghcrCreds == "" || registry1Creds == "" {
		t.Fatalf("GITHUB_TOKEN, GHCR_CREDS, and REGISTRY1_CREDS are required")
	}

	os.Args = []string{
		"program",
		"--registry-creds", ghcrCreds,
		"--registry-creds", registry1Creds,
		"--registry-creds", dockerCreds,
		"-n", "packages/uds/gitlab-runner",
		"--db-path", testDBPath,
		"-v", "2",
		"-t", github,
	}

	// Use a connection string for a test database

	db, err := setupDBConnection(testDBPath)
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
	// Check the number of rows in the scans table
	var count int64
	row := db.Model(&model.Scan{}).Count(&count)
	if err := row.Error; err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count <= 1 {
		t.Fatalf("Expected more than 1 row in scans table, got %d", count)
	}
	t.Logf("Scan %d rows", count)

	row = db.Model(&model.Package{}).Count(&count)
	if err := row.Error; err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if count <= 0 {
		t.Fatalf("Expected more than 0 row in package table, got %d", count)
	}
	t.Logf("Package %d rows", count)
}

func TestSetupDBConnection_Success(t *testing.T) {
	if os.Getenv("integration") != "true" {
		t.Skip("Skipping integration test")
	}
	// Use a connection string for a test database
	connStr := "uds_security_hub.db"

	db, err := setupDBConnection(connStr)
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
}
