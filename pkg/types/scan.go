package types

import (
	"context"
	"log/slog"

	"github.com/zarf-dev/zarf/src/api/v1beta1"
)

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

func (s ScanResult) GetArtifactName() string {
	return s.ArtifactName
}

func (s ScanResult) GetVulnerabilities() []VulnerabilityInfo {
	var allVulns []VulnerabilityInfo
	for _, r := range s.Results {
		allVulns = append(allVulns, r.Vulnerabilities...)
	}
	return allVulns
}

// ScanResultReader is an interface for reading scan results.
type ScanResultReader interface {
	// GetArtifactName returns the name of the scanned artifact.
	GetArtifactName() string

	// GetVulnerabilities returns a slice of VulnerabilityInfo representing the vulnerabilities
	// found in the scanned artifact.
	GetVulnerabilities() []VulnerabilityInfo
}

type ZarfPackage v1beta1.ZarfPackage

type PackageScannerResult struct {
	ArtifactNameOverride string
	JSONFilePath         string
}

type PackageScan struct {
	ZarfPackage ZarfPackage
	Results     []PackageScannerResult
}

// PackageScanner defines the methods required for scanning packages.
type PackageScanner interface {
	// Scan scans the package and returns the scan results.
	// Returns a slice of file paths containing the scan results in JSON format and an error if the scan operation fails.
	Scan(ctx context.Context) (*PackageScan, error)

	// ScanResultReader creates a new ScanResultReader from a JSON file.
	// Takes a trivy scan result file and returns a ScanResultReader.
	// Parameters:
	//   - jsonFilePath: The path to the JSON file containing the scan results.
	// Returns:
	//   - types.ScanResultReader: An instance of ScanResultReader that can be used to access the scan results.
	//   - error: An error if the file cannot be opened or the JSON cannot be decoded.
	ScanResultReader(result PackageScannerResult) (ScanResultReader, error)
}

// ScannerFactory defines the method to create a PackageScanner.
type ScannerFactory interface {
	// CreateScanner creates a new PackageScanner based on the provided options.
	// Parameters:
	//   - ctx: The context for the scanner.
	//   - logger: The logger to use for logging.
	//   - dockerConfigPath: The path to the Docker config file.
	//   - org: The organization name (for remote scanner).
	//   - packageName: The package name (for remote scanner).
	//   - tag: The tag name (for remote scanner).
	//   - packagePath: The path to the local package (for local scanner).
	// Returns:
	//   - PackageScanner: The created PackageScanner.
	//   - error: An error if the scanner cannot be created.
	CreateScanner(
		ctx context.Context,
		logger *slog.Logger,
		dockerConfigPath,
		org,
		packageName,
		tag,
		packagePath string,
	) (PackageScanner, error)
}
