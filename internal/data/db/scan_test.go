package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
)

// Convert external.ScanDTO to Scan.
func convertDTOToScan(dto *external.ScanDTO) model.Scan {
	return model.Scan{
		SchemaVersion:   dto.SchemaVersion,
		CreatedAt:       dto.CreatedAt,
		ArtifactName:    dto.ArtifactName,
		ArtifactType:    dto.ArtifactType,
		Metadata:        dto.Metadata,
		Vulnerabilities: dto.Vulnerabilities,
	}
}

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
				db: setupSQLiteDB(t),
				dto: external.ScanDTO{
					SchemaVersion: 1,
					CreatedAt:     time.Now(),
					ArtifactName:  "test-artifact",
					ArtifactType:  "container",
					Metadata: model.Metadata{
						RepoTags:    []string{"example-repo-tag"},
						RepoDigests: []string{"example-repo-digest"},
						ImageConfig: model.ImageConfig{
							Architecture: "x86_64",
							OS:           "linux",
						},
						DiffIDs: []string{"example-diff-id"},
					},
					Vulnerabilities: []model.Vulnerability{
						{
							PkgName: "CVE-1234",
						},
					},
				},
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
			// Fetch the scan from the database
			var fetchedScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&fetchedScan, "artifact_name = ?", tt.args.dto.ArtifactName).Error; err != nil {
				t.Fatalf("failed to fetch scan: %v", err)
			}
			dtoCopy := tt.args.dto
			// Convert dto to model.Scan for comparison
			expectedScan := convertDTOToScan(&dtoCopy)

			// Check if the fetched scan matches the inserted scan
			if diff := cmp.Diff(expectedScan, fetchedScan, cmpopts.IgnoreFields(model.Scan{}, "ID", "CreatedAt", "UpdatedAt")); diff != "" {
				t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
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
				db: setupSQLiteDB(t),
				dto: external.ScanDTO{
					SchemaVersion: 1,
					CreatedAt:     time.Now(),
					ArtifactName:  "test-artifact-updated",
					ArtifactType:  "container",
					Metadata:      model.Metadata{},
					Vulnerabilities: []model.Vulnerability{
						{
							PkgName: "CVE-5678",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.db.AutoMigrate(&model.Scan{}, &model.Vulnerability{})
			if err != nil {
				t.Fatalf("failed to auto-migrate Scan model: %v", err)
			}

			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}

			// Insert initial scan record
			initialDTO := external.ScanDTO{
				SchemaVersion: 1,
				CreatedAt:     time.Now(),
				ArtifactName:  "test-artifact",
				ArtifactType:  "container",
				Metadata: model.Metadata{
					RepoTags:    []string{"example-repo-tag"},
					RepoDigests: []string{"example-repo-digest"},
					ImageConfig: model.ImageConfig{
						Architecture: "x86_64",
						OS:           "linux",
					},
					DiffIDs: []string{"example-diff-id"},
				},
				Vulnerabilities: []model.Vulnerability{
					{
						PkgName: "CVE-1234",
					},
				},
			}
			if err := manager.InsertScan(context.Background(), &initialDTO); err != nil {
				t.Fatalf("failed to insert initial scan: %v", err)
			}

			// Fetch the initial scan to get its ID
			var initialScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&initialScan, "artifact_name = ?", initialDTO.ArtifactName).Error; err != nil {
				t.Fatalf("failed to fetch initial scan: %v", err)
			}

			// Update the inserted scan record
			dt := tt.args.dto
			dt.ID = initialScan.ID // Ensure the ID is set for the update
			if err := manager.UpdateScan(context.Background(), &dt); (err != nil) != tt.wantErr {
				t.Errorf("UpdateScan() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Fetch the updated scan from the database using the ID
			var fetchedScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&fetchedScan, "id = ?", dt.ID).Error; err != nil {
				t.Fatalf("failed to fetch updated scan: %v", err)
			}

			// Convert dto to model.Scan for comparison
			expectedScan := convertDTOToScan(&dt)

			// Check if the fetched scan matches the updated scan
			if diff := cmp.Diff(expectedScan, fetchedScan, cmpopts.IgnoreFields(model.Scan{}, "ID", "CreatedAt", "UpdatedAt")); diff != "" {
				t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
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
				db: setupSQLiteDB(t),
				id: 1, // This ID will be set after insertion
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.db.AutoMigrate(&model.Scan{}, &model.Vulnerability{})
			if err != nil {
				t.Fatalf("failed to auto-migrate Scan model: %v", err)
			}

			manager, err := NewGormScanManager(tt.args.db)
			if err != nil {
				t.Fatalf("failed to create scan manager: %v", err)
			}

			// Insert a scan record
			dto := external.ScanDTO{
				SchemaVersion: 1,
				CreatedAt:     time.Now(),
				ArtifactName:  "test-artifact",
				ArtifactType:  "container",
				Metadata: model.Metadata{
					RepoTags:    []string{"example-repo-tag"},
					RepoDigests: []string{"example-repo-digest"},
					ImageConfig: model.ImageConfig{
						Architecture: "x86_64",
						OS:           "linux",
					},
					DiffIDs: []string{"example-diff-id"},
				},
				Vulnerabilities: []model.Vulnerability{
					{
						PkgName: "CVE-1234",
					},
				},
			}
			if err := manager.InsertScan(context.Background(), &dto); err != nil {
				t.Fatalf("failed to insert scan: %v", err)
			}

			// Fetch the inserted scan to get its ID
			var insertedScan model.Scan
			if err := tt.args.db.Preload("Vulnerabilities").First(&insertedScan, "artifact_name = ?", dto.ArtifactName).Error; err != nil {
				t.Fatalf("failed to fetch inserted scan: %v", err)
			}

			// Update the test args with the inserted scan ID
			tt.args.id = insertedScan.ID

			// Fetch the scan using the GetScan method
			fetchedScan, err := manager.GetScan(context.Background(), tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetScan() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Convert dto to model.Scan for comparison
			expectedScan := convertDTOToScan(&dto)
			expectedScan.ID = insertedScan.ID // Ensure the ID matches

			// Check if the fetched scan matches the inserted scan
			if diff := cmp.Diff(&expectedScan, fetchedScan, cmpopts.IgnoreFields(model.Scan{}, "CreatedAt", "UpdatedAt")); diff != "" {
				t.Errorf("fetched scan mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
