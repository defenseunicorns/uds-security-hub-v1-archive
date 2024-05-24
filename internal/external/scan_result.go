package external

import (
	"time"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

type ScanResult struct {
	SchemaVersion int            `json:"SchemaVersion"`
	CreatedAt     time.Time      `json:"CreatedAt"`
	ArtifactName  string         `json:"ArtifactName"`
	ArtifactType  string         `json:"ArtifactType"`
	Metadata      model.Metadata `json:"Metadata"`
	Results       []struct {
		Target          string                `json:"Target"`
		Class           string                `json:"Class"`
		Type            string                `json:"Type"`
		Vulnerabilities []model.Vulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}
type ScanDTO struct {
	SchemaVersion   int
	CreatedAt       time.Time
	ArtifactName    string
	ArtifactType    string
	Metadata        model.Metadata
	Vulnerabilities []model.Vulnerability
}

func MapScanResultToDTO(result ScanResult) []ScanDTO {
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
