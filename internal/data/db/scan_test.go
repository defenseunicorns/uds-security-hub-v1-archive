package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"

	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

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
			if err != nil {
				t.Fatalf("failed to auto-migrate Scan model: %v", err)
			}
			if err := InsertScan(tt.args.db, tt.args.dto); (err != nil) != tt.wantErr {
				t.Errorf("InsertScan() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func setupSQLiteDB(t *testing.T) *gorm.DB {
	// Using a unique identifier for each database instance to ensure it's unique
	uniqueDBIdentifier := fmt.Sprintf("file:memdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(uniqueDBIdentifier), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	return db
}
