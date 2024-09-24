package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

type InitializerStub struct {
	err error
}

func (f *InitializerStub) Initialize(config *sql.DatabaseConfig) (*gorm.DB, error) {
	return nil, f.err
}

type MigratorStub struct {
	err error
}

func (f *MigratorStub) Migrate(dbConn gormMigrator) error {
	return f.err
}

func TestDatabaseMigrator(t *testing.T) {
	type testCase struct {
		name         string
		initializer  DatabaseInitializer
		migrator     DatabaseMigrator
		errSubstring string
	}

	testCases := []testCase{
		{
			name:         "fail to initialize",
			initializer:  &InitializerStub{err: fmt.Errorf("failed to initialize $$test$$")},
			errSubstring: "failed to initialize $$test$$",
		},
		{
			name:         "fail to migrate",
			initializer:  &InitializerStub{},
			migrator:     &MigratorStub{err: fmt.Errorf("failed to migrate $$test$$")},
			errSubstring: "failed to migrate $$test$$",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			testObj := &migratingDatabaseInitializer{
				initializer: tt.initializer,
				migrator:    tt.migrator,
			}

			_, err := testObj.Initialize(nil)

			if err == nil || !strings.Contains(err.Error(), tt.errSubstring) {
				t.Errorf("unexpected error; want %q, got %v", tt.errSubstring, err)
			}
		})
	}
}

type stubGormMigrator struct {
	err        error
	calledWith []interface{}
}

func (m *stubGormMigrator) AutoMigrate(models ...interface{}) error {
	m.calledWith = append([]interface{}{}, models...)
	return m.err
}

func TestMigrationFailure(t *testing.T) {
	expectedErr := "failed to automigrate $$mock$$"

	gormMigrator := &stubGormMigrator{
		err: errors.New(expectedErr),
	}

	migrator := &autoMigratingMigrator{}

	err := migrator.Migrate(gormMigrator)
	if err == nil {
		t.Fatal("expected err and got nil")
	}

	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("unexpected err; want: %q, got: %v", expectedErr, err)
	}

	expectedModels := []interface{}{&model.Package{}, &model.Scan{}, &model.Vulnerability{}, &model.Report{}}
	if diff := cmp.Diff(expectedModels, gormMigrator.calledWith); diff != "" {
		t.Fatalf("called with unexpected models: %s", diff)
	}
}

func TestSqliteDatabaseInitializer_Success(t *testing.T) {
	tmp, err := os.MkdirTemp("", "uds-security-hub-db-conn-*")
	if err != nil {
		t.Fatalf("failed to create tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	connStr := path.Join(tmp, "uds_security_hub.db")

	initializer := &sqliteDatabaseInitializer{}

	db, err := initializer.Initialize(&sql.DatabaseConfig{DBPath: connStr})
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

func TestSqliteDatabaseInitializer_Failure_Create_Dir(t *testing.T) {
	tmp, err := os.MkdirTemp("", "uds-security-hub-db-conn-*")
	if err != nil {
		t.Fatalf("failed to create tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	p := path.Join(tmp, "file")

	err = os.WriteFile(p, nil, 0o600)
	if err != nil {
		t.Fatalf("failed to create file for testing: %v", err)
	}

	initializer := &sqliteDatabaseInitializer{}

	_, err = initializer.Initialize(&sql.DatabaseConfig{DBPath: path.Join(p, "uds.db")})
	if err == nil {
		t.Fatal("exptected error, got nil")
	}

	expected := "failed to create directory for database"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("unexpected error; want: %q, got: %v", expected, err)
	}
}

func TestSqliteDatabaseInitializer_Failure_Bad_Sqlite_DB(t *testing.T) {
	tmp, err := os.MkdirTemp("", "uds-security-hub-db-conn-*")
	if err != nil {
		t.Fatalf("failed to create tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	dbFile := path.Join(tmp, "uds.db")

	err = os.WriteFile(dbFile, []byte("this is not the sqlite database you are looking for"), 0o600)
	if err != nil {
		t.Fatalf("failed to create file for testing: %v", err)
	}

	initializer := &sqliteDatabaseInitializer{}

	_, err = initializer.Initialize(&sql.DatabaseConfig{DBPath: dbFile})
	if err == nil {
		t.Fatal("exptected error, got nil")
	}

	expected := "failed to connect to database"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("unexpected error; want: %q, got: %v", expected, err)
	}
}
