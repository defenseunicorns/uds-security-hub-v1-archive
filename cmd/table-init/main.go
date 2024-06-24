package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

// migrateDatabase performs the database migrations.
func migrateDatabase(db *gorm.DB) error {
	err := db.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{})
	if err != nil {
		return fmt.Errorf("failed to auto-migrate models: %w", err)
	}
	return nil
}

// getEnv retrieves environment variables or returns a default value.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func main() {
	ctx := context.Background()

	// These default values are for local development with docker-compose.
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "test_user")
	password := getEnv("DB_PASSWORD", "test_password")
	dbname := getEnv("DB_NAME", "test_db")
	// This is the connection name for Cloud SQL. This will not be used for local development.
	instanceConnectionName := os.Getenv("INSTANCE_CONNECTION_NAME")

	connector := sql.CreateDBConnector(host, port, user, password, dbname, instanceConnectionName)
	db, err := connector.Connect(ctx)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// Perform database migration
	if err := migrateDatabase(db); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	// Close the database connection when the main function exits
	defer func() {
		sqlDB, err := db.DB()
		if err != nil {
			log.Fatalf("failed to get database connection: %v", err)
		}
		if err := sqlDB.Close(); err != nil {
			log.Fatalf("failed to close database connection: %v", err)
		}
		log.Println("Database connection closed")
	}()
}
