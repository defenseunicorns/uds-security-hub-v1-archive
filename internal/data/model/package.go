package model

import (
	"fmt"
	"time"

	"github.com/zarf-dev/zarf/src/api/v1beta1"
	"gorm.io/gorm"
)

// Package represents a collection of scans.
type Package struct {
	CreatedAt  time.Time           `json:"CreatedAt" gorm:"autoCreateTime"`
	UpdatedAt  time.Time           `json:"UpdatedAt" gorm:"autoUpdateTime"`
	Name       string              `json:"Name"`
	Repository string              `json:"Repository"`
	Tag        string              `json:"Tag"`
	Scans      []Scan              `json:"Scans" gorm:"foreignKey:PackageID;constraint:OnDelete:CASCADE"`
	ID         uint                `json:"ID" gorm:"primaryKey;autoIncrement"`
	Config     v1beta1.ZarfPackage `json:"Config" gorm:"serializer:json"`
}

// DeletePackagesByNameExceptTags deletes all packages with the given name except those with specified tags.
func DeletePackagesByNameExceptTags(db *gorm.DB, name string, excludeTags []string) error {
	if len(excludeTags) == 0 {
		return nil
	}
	if name == "" {
		return fmt.Errorf("name is required")
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		// Find packages to delete
		var packages []Package
		if err := tx.Where("name = ? AND tag NOT IN ?", name, excludeTags).Find(&packages).Error; err != nil {
			return fmt.Errorf("failed to find packages: %w", err)
		}

		// Delete related vulnerabilities and scans
		for i := range packages {
			pkg := &packages[i]
			var scans []Scan
			if err := tx.Where("package_id = ?", pkg.ID).Find(&scans).Error; err != nil {
				return fmt.Errorf("failed to find scans: %w", err)
			}
			for j := range scans {
				scan := &scans[j]
				if err := tx.Where("scan_id = ?", scan.ID).Delete(&Vulnerability{}).Error; err != nil {
					return fmt.Errorf("failed to delete vulnerabilities: %w", err)
				}
				if err := tx.Delete(&scan).Error; err != nil {
					return fmt.Errorf("failed to delete scan: %w", err)
				}
			}
		}

		// Delete packages
		if err := tx.Where("name = ? AND tag NOT IN ?", name, excludeTags).Delete(&Package{}).Error; err != nil {
			return fmt.Errorf("failed to delete packages: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}
	return nil
}
