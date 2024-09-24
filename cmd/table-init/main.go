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
	models := []interface{}{&model.Package{}, &model.Scan{}, &model.Vulnerability{}}
	for _, model := range models {
		err := db.AutoMigrate(model)
		if err != nil {
			log.Printf("failed to auto-migrate model: %v", err)
		}
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
	config := getConfig()

	if err := run(ctx, &config, sql.CreateDBConnector, migrateDatabase); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(
	ctx context.Context,
	config *sql.DatabaseConfig,
	connectorFactory func(*sql.DatabaseConfig) sql.DBConnector,
	migrator func(*gorm.DB) error,
) error {
	connector := connectorFactory(config)
	db, err := connector.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := migrator(db); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}

type Config struct {
	Host                   string
	Port                   string
	User                   string
	Password               string
	DBName                 string
	InstanceConnectionName string
}

func getConfig() sql.DatabaseConfig {
	return sql.DatabaseConfig{
		DBType:                   getEnv("DB_TYPE", ""),
		DBHost:                   getEnv("DB_HOST", "localhost"),
		DBPort:                   getEnv("DB_PORT", "5432"),
		DBUser:                   getEnv("DB_USER", "test_user"),
		DBPassword:               getEnv("DB_PASSWORD", "test_password"),
		DBName:                   getEnv("DB_NAME", "test_db"),
		DBInstanceConnectionName: os.Getenv("INSTANCE_CONNECTION_NAME"),
	}
}
