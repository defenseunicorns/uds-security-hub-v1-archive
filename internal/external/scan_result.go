package external

import (
	"encoding/json"
	"time"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

// go:bui
// ScanResult is a struct that represents the scan result.
type ScanResult struct {
	Metadata     model.Metadata `json:"Metadata"`
	CreatedAt    time.Time      `json:"CreatedAt"`
	ArtifactName string         `json:"ArtifactName"`
	ArtifactType string         `json:"ArtifactType"`
	Results      []struct {
		Target          string                `json:"Target"`
		Class           string                `json:"Class"`
		Type            string                `json:"Type"`
		Vulnerabilities []model.Vulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
	SchemaVersion int  `json:"SchemaVersion"`
	ID            uint `json:"ID"`
}

// ScanDTO is a struct that represents the scan data transfer object.
type ScanDTO struct {
	CreatedAt       time.Time             `json:"CreatedAt"`
	ArtifactName    string                `json:"ArtifactName"`
	ArtifactType    string                `json:"ArtifactType"`
	Metadata        json.RawMessage       `json:"Metadata"`
	Vulnerabilities []model.Vulnerability `json:"Vulnerabilities"`
	ID              uint                  `json:"ID"`
	SchemaVersion   int                   `json:"SchemaVersion"`
	PackageID       uint                  `json:"PackageID"`
}

// PackageDTO is a struct that represents the package data transfer object.
type PackageDTO struct {
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Name       string
	Repository string
	Tag        string
	Scans      []ScanDTO
	ID         uint
}

// MapScanResultToDTO maps the ScanResult to a slice of ScanDTO.
func MapScanResultToDTO(result *ScanResult) []ScanDTO {
	var dtos []ScanDTO
	for _, res := range result.Results {
		metadataJSON, err := json.Marshal(result.Metadata)
		if err != nil {
			// Handle error appropriately
			continue
		}
		dto := ScanDTO{
			ID:              result.ID,
			SchemaVersion:   result.SchemaVersion,
			CreatedAt:       result.CreatedAt,
			ArtifactName:    result.ArtifactName,
			ArtifactType:    result.ArtifactType,
			Metadata:        json.RawMessage(metadataJSON),
			Vulnerabilities: res.Vulnerabilities,
		}
		dtos = append(dtos, dto)
	}
	return dtos
}

// MapPackageToDTO maps the Package to a PackageDTO.
func MapPackageToDTO(pkg *model.Package) PackageDTO {
	var scanDTOs []ScanDTO
	for i := range pkg.Scans {
		scan := &pkg.Scans[i]
		scanDTO := ScanDTO{
			ID:              scan.ID,
			SchemaVersion:   scan.SchemaVersion,
			CreatedAt:       scan.CreatedAt,
			ArtifactName:    scan.ArtifactName,
			ArtifactType:    scan.ArtifactType,
			Metadata:        scan.Metadata,
			Vulnerabilities: scan.Vulnerabilities,
		}
		scanDTOs = append(scanDTOs, scanDTO)
	}

	return PackageDTO{
		ID:         pkg.ID,
		CreatedAt:  pkg.CreatedAt,
		UpdatedAt:  pkg.UpdatedAt,
		Name:       pkg.Name,
		Repository: pkg.Repository,
		Tag:        pkg.Tag,
		Scans:      scanDTOs,
	}
}
