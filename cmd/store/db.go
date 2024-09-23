package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

type DatabaseInitializer interface {
	Initialize(config *DatabaseConfig) (*gorm.DB, error)
}

type defaultDatabaseInitializer struct{}

func (d *defaultDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	initializer := getInitializer(config)

	return initializer.Initialize(config)
}

type sqliteDatabaseInitializer struct{}

func (s *sqliteDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(config.DBPath), os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create directory for database: %w", err)
	}

	dbConn, err := gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return dbConn, nil
}

type postgresDatabaseInitializer struct{}

func (p *postgresDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	connector := sql.CreateDBConnector(
		config.DBType, config.DBPath, config.DBInstanceConnectionName,
		config.DBUser, config.DBPassword, config.DBName,
	)
	dbConn, err := connector.Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return dbConn, nil
}

func getInitializer(config *DatabaseConfig) DatabaseInitializer {
	if config.DBType == "sqlite" {
		return &sqliteDatabaseInitializer{}
	}

	return &postgresDatabaseInitializer{}
}

type DatabaseMigrator interface {
	Migrate(dbConn gormMigrator) error
}

type gormMigrator interface {
	AutoMigrate(...interface{}) error
}

type autoMigratingMigrator struct{}

func (d *autoMigratingMigrator) Migrate(dbConn gormMigrator) error {
	err := dbConn.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{}, &model.Report{})
	if err != nil {
		return fmt.Errorf("failed to migrate: %w", err)
	}

	return nil
}

var DefaultDatabaseInitializer DatabaseInitializer = &migratingDatabaseInitializer{
	initializer: &defaultDatabaseInitializer{},
	migrator:    &autoMigratingMigrator{},
}

type migratingDatabaseInitializer struct {
	initializer DatabaseInitializer
	migrator    DatabaseMigrator
}

func (d *migratingDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	dbConn, err := d.initializer.Initialize(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	if err := d.migrator.Migrate(dbConn); err != nil {
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return dbConn, nil
}
