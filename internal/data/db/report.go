package db

import (
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

// InsertReport inserts a new report into the database.
func InsertReport(db *gorm.DB, report *model.Report) error {
	return db.Create(report).Error
}

// GetReport retrieves a report by its ID from the database.
func GetReport(db *gorm.DB, id uint) (*model.Report, error) {
	var report model.Report
	if err := db.First(&report, id).Error; err != nil {
		return nil, err
	}
	return &report, nil
}
