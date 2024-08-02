package scan

import (
	"bytes"
	"encoding/csv"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type scanResultReader struct {
	ArtifactNameOverride string
	scanResult           types.ScanResult
}

// GetArtifactName returns the artifact name in the scan result.
func (s *scanResultReader) GetArtifactName() string {
	if s.ArtifactNameOverride != "" {
		return s.ArtifactNameOverride
	}
	return s.scanResult.ArtifactName
}

// GetVulnerabilities returns the vulnerabilities in the scan result.
// It assumes there is only one set of results in the scan result.
// If there are no results, it returns an empty slice.
func (s *scanResultReader) GetVulnerabilities() []types.VulnerabilityInfo {
	if len(s.scanResult.Results) == 0 {
		return []types.VulnerabilityInfo{}
	}
	return s.scanResult.Results[0].Vulnerabilities
}

// GetResultsAsCSV returns the scan results in CSV format.
// The CSV format includes the following columns:
// ArtifactName, VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Description
// Each row represents a single vulnerability found in the scanned artifact.
func (s *scanResultReader) GetResultsAsCSV() string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	w.Write([]string{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"})

	vulnerabilities := s.GetVulnerabilities()
	for _, vuln := range vulnerabilities {
		w.Write([]string{
			s.GetArtifactName(),
			vuln.VulnerabilityID,
			vuln.PkgName,
			vuln.InstalledVersion,
			vuln.FixedVersion,
			vuln.Severity,
			vuln.Description,
		})
	}

	w.Flush()

	return buf.String()
}
