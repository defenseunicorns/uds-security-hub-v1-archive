package main

import (
	"os"
	"testing"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

// TestStore is a test for the store command e2e.
func TestStore(t *testing.T) {

	userName := os.Getenv("REGISTRY1_USERNAME")
	password := os.Getenv("REGISTRY1_PASSWORD")
	github := os.Getenv("GITHUB_TOKEN")
	if github == "" {
		t.Fatalf("GITHUB_TOKEN is required")
	}
	os.Args = []string{
		"program", // the program name, typically the executable name
		"-o", "defenseunicorns",
		"-n", "packages/uds/gitlab-runner",
		"-u", userName,
		"-p", password,
		"-t", github,
	}

	main()

	// Use a connection string for a test database
	connStr := "host=localhost port=5432 user=test_user dbname=test_db password=test_password sslmode=disable"

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
	// Use a connection string for a test database
	connStr := "host=localhost port=5432 user=test_user dbname=test_db password=test_password sslmode=disable"

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
