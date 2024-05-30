package external

import (
	"time"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

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
	SchemaVersion int `json:"SchemaVersion"`
}

// ScanDTO is a struct that represents the scan data transfer object.
type ScanDTO struct {
	Metadata        model.Metadata
	CreatedAt       time.Time
	ArtifactName    string
	ArtifactType    string
	Vulnerabilities []model.Vulnerability
	SchemaVersion   int
}

// MapScanResultToDTO maps the ScanResult to a slice of ScanDTO.
func MapScanResultToDTO(result *ScanResult) []ScanDTO {
	var dtos []ScanDTO
	for _, res := range result.Results {
		dto := ScanDTO{
			SchemaVersion:   result.SchemaVersion,
			CreatedAt:       result.CreatedAt,
			ArtifactName:    result.ArtifactName,
			ArtifactType:    result.ArtifactType,
			Metadata:        result.Metadata,
			Vulnerabilities: res.Vulnerabilities,
		}
		dtos = append(dtos, dto)
	}
	return dtos
}
