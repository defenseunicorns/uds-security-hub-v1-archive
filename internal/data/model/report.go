package model

import (
	"encoding/json"
	"time"
)

// Report represents a report of a scan.
type Report struct {
	CreatedAt   time.Time       `json:"CreatedAt" gorm:"autoCreateTime"`
	PackageName string          `json:"PackageName" gorm:"not null" index:"idx_package_name"`
	Tag         string          `json:"Tag" gorm:"not null" index:"idx_tag"`
	SBOM        json.RawMessage `json:"SBOM" gorm:"type:jsonb"`
	ID          uint            `json:"ID" gorm:"primaryKey;autoIncrement"`
	Critical    int             `json:"Critical"`
	High        int             `json:"High"`
	Medium      int             `json:"Medium"`
	Low         int             `json:"Low"`
	Info        int             `json:"Info"`
	Total       int             `json:"Total"`
}
