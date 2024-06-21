package main

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

func setupDBConnection(connStr string) (*gorm.DB, error) {
	database, err := gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Check if migration is needed by checking for the existence of the tables
	err = database.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{})
	if err != nil {
		return nil, fmt.Errorf("failed to auto-migrate models: %w", err)
	}

	return database, nil
}

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "host=localhost port=5432 user=test_user dbname=test_db password=test_password sslmode=disable"
	}
	_, err := setupDBConnection(connStr)
	if err != nil {
		log.Fatalf("failed to setup database connection: %v", err)
	}
}
