package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type DatabaseInitializer interface {
	Initialize(config *Config, logger types.Logger) (*gorm.DB, error)
}

type defaultDatabaseInitializer struct{}

func (d *defaultDatabaseInitializer) Initialize(config *Config, logger types.Logger) (*gorm.DB, error) {
	connector := sql.CreateDBConnector(
		config.DBType, config.DBPath, config.DBInstanceConnectionName,
		config.DBUser, config.DBPassword, config.DBName,
	)

	dbConn, err := connector.Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// this is for local sqlite db path and we would need to initialize the db and tables
	if config.DBType == "sqlite" {
		logger.Info("Using local SQLite database", zap.String("dbPath", config.DBPassword))
		dbConn, err = setupDBConnection(config.DBPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to setup database connection: %w", err)
		}
	}

	return dbConn, nil
}

type DatabaseMigrator interface {
	Migrate(dbConn *gorm.DB) error
}

type autoMigratingMigrator struct{}

func (d *autoMigratingMigrator) Migrate(dbConn *gorm.DB) error {
	return dbConn.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{}, &model.Report{})
}

type migratingDatabaseInitializer struct {
	initializer DatabaseInitializer
	migrator    DatabaseMigrator
}

var DefaultDatabaseInitializer = &migratingDatabaseInitializer{
	initializer: &defaultDatabaseInitializer{},
	migrator:    &autoMigratingMigrator{},
}

func (d *migratingDatabaseInitializer) Initialize(config *Config, logger types.Logger) (*gorm.DB, error) {
	if d.initializer == nil {
		d.initializer = &defaultDatabaseInitializer{}
	}
	if d.migrator == nil {
		d.migrator = &autoMigratingMigrator{}
	}

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
