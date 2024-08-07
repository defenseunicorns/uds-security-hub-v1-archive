package scan

import (
	"encoding/csv"
	"fmt"
	"io"

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

func (s *scanResultReader) WriteToCSV(w io.Writer, includeHeader bool) error {
	csvWriter := csv.NewWriter(w)

	if includeHeader {
		err := csvWriter.Write([]string{
			"ArtifactName",
			"VulnerabilityID",
			"PkgName",
			"InstalledVersion",
			"FixedVersion",
			"Severity",
			"Description",
		})
		if err != nil {
			return fmt.Errorf("error writing csv header: %w", err)
		}
	}

	vulnerabilities := s.GetVulnerabilities()
	for _, vuln := range vulnerabilities {
		err := csvWriter.Write([]string{
			s.GetArtifactName(),
			vuln.VulnerabilityID,
			vuln.PkgName,
			vuln.InstalledVersion,
			vuln.FixedVersion,
			vuln.Severity,
			vuln.Description,
		})
		if err != nil {
			return fmt.Errorf("error writing csv record: %w", err)
		}
	}

	csvWriter.Flush()

	return nil
}
