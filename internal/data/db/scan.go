package db

import (
	"fmt"
	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"gorm.io/gorm"
)

// InsertScan inserts a new Scan and its associated Vulnerabilities into the database.
func InsertScan(db *gorm.DB, dto external.ScanDTO) error {
	if db == nil {
		return fmt.Errorf("db cannot be nil")
	}
	scan := model.Scan{
		SchemaVersion:   dto.SchemaVersion,
		CreatedAt:       dto.CreatedAt,
		ArtifactName:    dto.ArtifactName,
		ArtifactType:    dto.ArtifactType,
		Metadata:        dto.Metadata,
		Vulnerabilities: dto.Vulnerabilities,
	}

	if err := db.Create(&scan).Error; err != nil {
		return fmt.Errorf("error creating scan: %v", err)
	}
	return nil
}
