package external

import (
	"encoding/json"
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
func MapScanResultToDTO(result *ScanResult) ScanDTO {
	dto := ScanDTO{
		ID:            result.ID,
		SchemaVersion: result.SchemaVersion,
		ArtifactName:  result.ArtifactName,
		ArtifactType:  result.ArtifactType,
		CreatedAt:     result.CreatedAt,
	}
	dto.Metadata, _ = json.Marshal(result.Metadata) //nolint:errcheck

	// there can be multiple results per scan, we want to take all of the vulns
	// and map them to a single ScanDTO
	for _, res := range result.Results {
		for i := range res.Vulnerabilities {
			vuln := res.Vulnerabilities[i]

			// copy these fields over, they are not in the vulnerability
			// and exist in the result
			vuln.Target = res.Target
			vuln.Type = res.Type
			vuln.Class = res.Class

			dto.Vulnerabilities = append(dto.Vulnerabilities, vuln)
		}
	}

	return dto
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

// MapPackageDTOToReport maps the PackageDTO to a Report.
func MapPackageDTOToReport(dto *PackageDTO, sbom []byte) *model.Report {
	const (
		Critical = "CRITICAL"
		High     = "HIGH"
		Medium   = "MEDIUM"
		Low      = "LOW"
		Info     = "INFO"
	)
	return &model.Report{
		CreatedAt:   dto.CreatedAt,
		PackageName: dto.Name,
		Tag:         dto.Tag,
		SBOM:        sbom,
		Critical:    countVulnerabilities(dto.Scans, Critical),
		High:        countVulnerabilities(dto.Scans, High),
		Medium:      countVulnerabilities(dto.Scans, Medium),
		Low:         countVulnerabilities(dto.Scans, Low),
		Info:        countVulnerabilities(dto.Scans, Info),
		Total:       countTotalVulnerabilities(dto.Scans),
	}
}

// countVulnerabilities counts the number of vulnerabilities of a specific severity in the scans.
func countVulnerabilities(scans []ScanDTO, severity string) int {
	count := 0
	for i := range scans {
		for j := range scans[i].Vulnerabilities {
			if scans[i].Vulnerabilities[j].Severity == severity {
				count++
			}
		}
	}
	return count
}

// countTotalVulnerabilities counts the total number of vulnerabilities in the scans.
func countTotalVulnerabilities(scans []ScanDTO) int {
	count := 0
	for i := range scans {
		count += len(scans[i].Vulnerabilities)
	}
	return count
}
