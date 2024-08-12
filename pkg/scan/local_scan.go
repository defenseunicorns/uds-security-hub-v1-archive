package scan

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func extractFilesFromTar(r io.Reader, filenames ...string) (map[string][]byte, error) {
	tarReader := tar.NewReader(r)

	results := make(map[string][]byte)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read package tar header: %w", err)
		}

		if slices.Contains(filenames, header.Name) {
			sbomTar, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %q: %w", header.Name, err)
			}
			results[header.Name] = sbomTar
		}
	}

	return results, nil
}

// LocalPackageScanner is a struct that holds the logger and paths for docker configuration and package.
type LocalPackageScanner struct {
	logger        types.Logger
	packagePath   string
	offlineDBPath string // New field for offline DB path
}

// NewLocalPackageScanner creates a new LocalPackageScanner instance.
// Parameters:
// - logger: the logger to use for logging.
// - dockerConfigPath: the path to the docker configuration file.
// - packagePath: the path to the zarf package to scan.
// - offlineDBPath: the path to the offline DB for Trivy.
// Returns:
// - *LocalPackageScanner: the LocalPackageScanner instance.
// - error: an error if the instance cannot be created.
func NewLocalPackageScanner(logger types.Logger,
	packagePath, offlineDBPath string) (types.PackageScanner, error) {
	if packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	return &LocalPackageScanner{
		logger:        logger,
		packagePath:   packagePath,
		offlineDBPath: offlineDBPath,
	}, nil
}

// Scan scans the package and returns the scan results which are trivy scan results in json format.
// Parameters:
// - ctx: the context to use for the scan.
// Returns:
// - []string: the scan results which are trivy scan results in json format.
// - error: an error if the scan fails.
func (lps *LocalPackageScanner) Scan(ctx context.Context) ([]types.PackageScannerResult, error) {
	if lps.packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	commandExecutor := executor.NewCommandExecutor(ctx)
	rootfsResult, err := ExtractRootFS(lps.logger, lps.packagePath, commandExecutor)
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from tar: %w", err)
	}
	var scanResults []types.PackageScannerResult
	for _, rootfs := range rootfsResult.Refs {
		scanResult, err := scanWithTrivy(rootfs, "", lps.offlineDBPath, commandExecutor)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rootfs %s: %w", rootfs.RootFSDir, err)
		}
		scanResults = append(scanResults, types.PackageScannerResult{
			ArtifactNameOverride: rootfs.ArtifactName,
			JSONFilePath:         scanResult,
		})
	}

	// this error should fail the scanner, but we want to know about it
	if err := rootfsResult.Cleanup(); err != nil {
		lps.logger.Warn("error cleaning up rootfsResult: %s", err)
	}

	return scanResults, nil
}

// ScanResultReader reads the scan result from the json file and returns the scan result.
// Parameters:
// - jsonFilePath: the path to the json file to read the scan result from.
// Returns:
// - types.ScanResultReader: the scan result.
// - error: an error if the reading fails.
func (lps *LocalPackageScanner) ScanResultReader(result types.PackageScannerResult) (types.ScanResultReader, error) {
	file, err := os.Open(result.JSONFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JSON file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	if err := json.NewDecoder(file).Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("failed to decode JSON file: %w", err)
	}

	return &scanResultReader{ArtifactNameOverride: result.ArtifactNameOverride, scanResult: scanResult}, nil
}
