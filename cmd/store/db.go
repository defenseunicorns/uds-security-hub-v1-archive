package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type DatabaseInitializer interface {
	Initialize(config *DatabaseConfig, logger types.Logger) (*gorm.DB, error)
}

type defaultDatabaseInitializer struct{}

func (d *defaultDatabaseInitializer) Initialize(config *DatabaseConfig, logger types.Logger) (*gorm.DB, error) {
	connector := sql.CreateDBConnector(
		config.DBType, config.DBPath, config.DBInstanceConnectionName,
		config.DBUser, config.DBPassword, config.DBName,
	)

	// this is for local sqlite db path and we would need to initialize the db and tables
	if config.DBType == "sqlite" {
		logger.Info("Using local SQLite database", zap.String("dbPath", config.DBPath))
		dbConn, err := setupDBConnection(config.DBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to setup database connection: %w", err)
		}
		return dbConn, nil
	} else {
		dbConn, err := connector.Connect(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		return dbConn, nil
	}
}

type DatabaseMigrator interface {
	Migrate(dbConn *gorm.DB) error
}

type autoMigratingMigrator struct{}

func (d *autoMigratingMigrator) Migrate(dbConn *gorm.DB) error {
	err := dbConn.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{}, &model.Report{})
	if err != nil {
		return fmt.Errorf("failed to migrate: %w", err)
	}

	return nil
}

type migratingDatabaseInitializer struct {
	initializer DatabaseInitializer
	migrator    DatabaseMigrator
}

var DefaultDatabaseInitializer DatabaseInitializer = &migratingDatabaseInitializer{
	initializer: &defaultDatabaseInitializer{},
	migrator:    &autoMigratingMigrator{},
}

func (d *migratingDatabaseInitializer) Initialize(config *DatabaseConfig, logger types.Logger) (*gorm.DB, error) {
	dbConn, err := d.initializer.Initialize(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	if err := d.migrator.Migrate(dbConn); err != nil {
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return dbConn, nil
}

func setupDBConnection(dbPath string) (*gorm.DB, error) {
	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create directory for database: %w", err)
	}

	database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return database, nil
}
