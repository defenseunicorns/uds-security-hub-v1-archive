package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
)

// TestInsertScan tests the InsertScan method of the GormScanManager.
func TestInsertScan(t *testing.T) {
	type args struct {
		db  *gorm.DB
		dto external.ScanDTO
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful insertion",
			args: args{
				db:  setupSQLiteDB(t),
				dto: external.ScanDTO{SchemaVersion: 1, CreatedAt: time.Now(), ArtifactName: "test-artifact", ArtifactType: "container", Metadata: model.Metadata{}, Vulnerabilities: []model.Vulnerability{}},
			},
			wantErr: false,
		},
	}
	// Auto-migrate the Scan model
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.db.AutoMigrate(&model.Scan{}, &model.Vulnerability{})
			dto := tt.args.dto
			if err != nil {
				t.Fatalf("failed to auto-migrate Scan model: %v", err)
			}
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}
			if err := manager.InsertScan(context.Background(), &dto); (err != nil) != tt.wantErr {
				t.Errorf("InsertScan() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// setupSQLiteDB sets up a SQLite database for testing.
func setupSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper() // Mark this function as a test helper
	// Using a unique identifier for each database instance to ensure it's unique
	uniqueDBIdentifier := fmt.Sprintf("file:memdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(uniqueDBIdentifier), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	return db
}

// TestUpdateScan tests the UpdateScan method of the GormScanManager.
func TestUpdateScan(t *testing.T) {
	type args struct {
		db  *gorm.DB
		dto external.ScanDTO
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful update",
			args: args{
				db:  setupSQLiteDB(t),
				dto: external.ScanDTO{SchemaVersion: 1, CreatedAt: time.Now(), ArtifactName: "test-artifact-updated", ArtifactType: "container", Metadata: model.Metadata{}, Vulnerabilities: []model.Vulnerability{}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}
			if err := manager.UpdateScan(context.Background(), &tt.args.dto); (err != nil) != tt.wantErr {
				t.Errorf("UpdateScan() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGetScan tests the GetScan method of the GormScanManager.
func TestGetScan(t *testing.T) {
	type args struct {
		db *gorm.DB
		id uint
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "successful retrieval",
			args: args{
				db:  setupSQLiteDB(t),
				id: 1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}
			_, err = manager.GetScan(context.Background(), tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetScan() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
