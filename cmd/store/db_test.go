package main

import (
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type InitializerStub struct {
	err error
}

func (f *InitializerStub) Initialize(config DatabaseConfig, logger types.Logger) (*gorm.DB, error) {
	return nil, f.err
}

type MigratorStub struct {
	err error
}

func (f *MigratorStub) Migrate(dbConn *gorm.DB) error {
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

			_, err := testObj.Initialize(DatabaseConfig{}, nil)

			if err == nil || !strings.Contains(err.Error(), tt.errSubstring) {
				t.Errorf("unexpected error; want %q, got %v", tt.errSubstring, err)
			}
		})
	}
}
