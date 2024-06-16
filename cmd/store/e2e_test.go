//go:build integration
// +build integration

package main

import (
	"os"
	"testing"
)

// TestStore is a test for the store command e2e.
func TestStore(t *testing.T) {
	userName := os.Getenv("REGISTRY1_USERNAME")
	password := os.Getenv("REGISTRY1_PASSWORD")
	os.Args = []string{
		"program", // the program name, typically the executable name
		"-o", "defenseunicorns",
		"-n", "packages/uds/gitlab-runner",
		"-g", "16.10.0-uds.0-upstream",
		"-u", userName,
		"-p", password,
	}

	main()
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
