package types

// VulnerabilityInfo represents information about a vulnerability found in a scanned artifact.
type VulnerabilityInfo struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
}

// ScanResult represents the result of scanning an artifact for vulnerabilities.
type ScanResult struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Vulnerabilities []VulnerabilityInfo `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanResultReader is an interface for reading scan results.
type ScanResultReader interface {
	// GetArtifactName returns the name of the scanned artifact.
	GetArtifactName() string
	// GetVulnerabilities returns a slice of VulnerabilityInfo representing the vulnerabilities
	// found in the scanned artifact.
	GetVulnerabilities() []VulnerabilityInfo
	// GetResultsAsCSV returns the scan results in CSV format.
	GetResultsAsCSV() string
}
