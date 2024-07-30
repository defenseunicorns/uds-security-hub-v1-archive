package model

import "time"

// Package represents a collection of scans.
type Package struct {
	CreatedAt  time.Time `json:"CreatedAt" gorm:"autoCreateTime"`
	UpdatedAt  time.Time `json:"UpdatedAt" gorm:"autoUpdateTime"`
	Name       string    `json:"Name"`
	Repository string    `json:"Repository"`
	Tag        string    `json:"Tag"`
	Scans      []Scan    `json:"Scans" gorm:"foreignKey:PackageID"`
	ID         uint      `json:"ID" gorm:"primaryKey;autoIncrement"`
}
