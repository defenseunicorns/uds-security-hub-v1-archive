package scan

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type localScanResult struct {
	types.ScanResult
}

// GetArtifactName returns the artifact name in the scan result.
func (s *localScanResult) GetArtifactName() string {
	return s.ArtifactName
}

// Scanner implements the PackageScanner interface for remote packages.
type Scanner struct {
	logger           types.Logger
	ctx              context.Context
	commandExecutor  types.CommandExecutor
	dockerConfigPath string
	org              string
	packageName      string
	tag              string
}

// NewRemotePackageScanner creates a new Scanner for remote packages.
func NewRemotePackageScanner(
	ctx context.Context,
	logger types.Logger,
	dockerConfigPath,
	org,
	packageName,
	tag string,
) types.PackageScanner {
	return &Scanner{
		logger:           logger,
		commandExecutor:  executor.NewCommandExecutor(ctx),
		dockerConfigPath: dockerConfigPath,
		org:              org,
		packageName:      packageName,
		tag:              tag,
	}
}

// GetVulnerabilities returns the vulnerabilities in the scan result.
// It assumes there is only one set of results in the scan result.
// If there are no results, it returns an empty slice.
func (s *localScanResult) GetVulnerabilities() []types.VulnerabilityInfo {
	if len(s.Results) == 0 {
		return []types.VulnerabilityInfo{}
	}
	return s.Results[0].Vulnerabilities
}

// GetResultsAsCSV returns the scan results in CSV format.
// The CSV format includes the following columns:
// ArtifactName, VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Description
// Each row represents a single vulnerability found in the scanned artifact.
func (s *localScanResult) GetResultsAsCSV() string {
	var sb strings.Builder
	sb.WriteString("\"ArtifactName\",\"VulnerabilityID\",\"PkgName\",\"InstalledVersion\",\"FixedVersion\",\"Severity\",\"Description\"\n") //nolint:lll

	vulnerabilities := s.GetVulnerabilities()
	for _, vuln := range vulnerabilities {
		sb.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			s.GetArtifactName(),
			vuln.VulnerabilityID,
			vuln.PkgName,
			vuln.InstalledVersion,
			vuln.FixedVersion,
			vuln.Severity,
			vuln.Description))
	}
	return sb.String()
}

// ScanResultReader creates a new ScanResultReader from a JSON file.
// This takes a trivy scan result file and returns a ScanResultReader.
//
// Parameters:
//   - jsonFilePath: The path to the JSON file containing the scan results.
//
// Returns:
//   - types.ScanResultReader: An instance of ScanResultReader that can be used to access the scan results.
//   - error: An error if the file cannot be opened or the JSON cannot be decoded.
func (s *Scanner) ScanResultReader(jsonFilePath string) (types.ScanResultReader, error) {
	if jsonFilePath == "" {
		return nil, fmt.Errorf("jsonFilePath cannot be empty")
	}

	file, err := os.Open(jsonFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	return &localScanResult{ScanResult: scanResult}, nil
}

// ScanZarfPackage scans a Zarf package and returns the scan results.
//
// Parameters:
//   - org: The organization that owns the package.
//   - packageName: The name of the package to scan.
//   - tag: The tag of the package to scan.
//
// Returns:
//   - []string: A slice of file paths containing the scan results in JSON format.
//   - error: An error if the scan operation fails.
func (s *Scanner) ScanZarfPackage(org, packageName, tag string) ([]string, error) {
	s.org = org
	s.packageName = packageName
	s.tag = tag
	return s.Scan(s.ctx)
}

// Scan scans the remote package and returns the scan results.
func (s *Scanner) Scan(ctx context.Context) ([]string, error) {
	if s.org == "" {
		return nil, fmt.Errorf("org cannot be empty")
	}
	if s.packageName == "" {
		return nil, fmt.Errorf("packageName cannot be empty")
	}
	if s.tag == "" {
		return nil, fmt.Errorf("tag cannot be empty")
	}
	//nolint:contextcheck
	commandExecutor := executor.NewCommandExecutor(s.ctx)
	imageRef := fmt.Sprintf("ghcr.io/%s/%s:%s", s.org, s.packageName, s.tag)

	//nolint:contextcheck
	results, err := s.scanImageAndProcessResults(s.ctx, imageRef, s.dockerConfigPath, commandExecutor)
	if err != nil {
		return nil, fmt.Errorf("failed to scan and process image: %w", err)
	}
	return results, nil
}

// scanImageAndProcessResults scans an image reference and processes the results.
//
// Parameters:
//   - ctx: The context for the scan operation.
//   - imageRef: The reference to the image to scan.
//   - dockerConfigPath: The path to the Docker config file.
//   - executor: The command executor to use for running commands.
//
// Returns:
//   - []string: A slice of file paths containing the scan results in JSON format.
//   - error: An error if the scan operation fails.
func (s *Scanner) scanImageAndProcessResults(ctx context.Context, imageRef, dockerConfigPath string,
	commandExecutor types.CommandExecutor) ([]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	idx, err := s.fetchImageIndex(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image index: %w", err)
	}

	results, err := s.processImageIndex(ctx, idx, dockerConfigPath, commandExecutor)
	if err != nil {
		return nil, fmt.Errorf("failed to process image index: %w", err)
	}

	return results, nil
}

// fetchImageIndex fetches the image index for the given reference.
//
// Parameters:
//   - ctx: The context for the fetch operation (unused).
//   - ref: The reference to the image index to fetch.
//
// Returns:
//   - v1.ImageIndex: The fetched image index.
//   - error: An error if the fetch operation fails.
func (s *Scanner) fetchImageIndex(_ context.Context, ref name.Reference) (v1.ImageIndex, error) {
	idx, err := remote.Index(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image index: %w", err)
	}
	return idx, nil
}

// processImageIndex processes an image index, extracting SBOMs and running trivy on the SBOM.
//
// Parameters:
//   - ctx: The context for the processing operation.
//   - idx: The image index to process.
//   - dockerConfigPath: The path to the Docker config file.
//   - executor: The command executor to use for running commands.
//
// Returns:
//   - []string: A slice of file paths containing the scan results in JSON format.
//   - error: An error if the processing operation fails.
func (s *Scanner) processImageIndex(ctx context.Context, idx v1.ImageIndex, dockerConfigPath string,
	commandExecutor types.CommandExecutor) ([]string, error) {
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("error fetching index manifest: %w", err)
	}

	var results []string
	for i := range indexManifest.Manifests {
		manifestDescriptor := &indexManifest.Manifests[i] // Use a pointer to the element
		image, err := idx.Image(manifestDescriptor.Digest)
		if err != nil {
			return nil, fmt.Errorf("error fetching image: %w", err)
		}

		manifestResults, err := s.processImageManifest(ctx, image, dockerConfigPath, commandExecutor)
		if err != nil {
			return nil, fmt.Errorf("error processing image manifest: %w", err)
		}
		// Only process the first image manifest to avoid redundant scans
		results = append(results, manifestResults...)
	}

	return results, nil
}

// processImageManifest processes an image manifest, extracting SBOMs and running Trivy on them.
//
// Parameters:
//   - ctx: The context for the processing operation.
//   - image: The image manifest to process.
//   - dockerConfigPath: The path to the Docker config file.
//   - executor: The command executor to use for running commands.
//
// Returns:
//   - []string: A slice of file paths containing the scan results in JSON format.
//   - error: An error if the processing operation fails.
func (s *Scanner) processImageManifest(ctx context.Context, image v1.Image, dockerConfigPath string,
	commandExecutor types.CommandExecutor) ([]string, error) {
	const sbomsTarLayer = "sboms.tar"
	manifest, err := image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("error fetching image manifest: %w", err)
	}

	var results []string
	var errs error

	for i := range manifest.Layers {
		layerDescriptor := &manifest.Layers[i] // Use a pointer to the element
		title, ok := layerDescriptor.Annotations["org.opencontainers.image.title"]
		if !ok || title != sbomsTarLayer {
			continue // Skip layers without the title annotation or title not equal to sboms.tar
		}

		layer, err := image.LayerByDigest(layerDescriptor.Digest)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("error fetching sboms.tar layer: %w", err))
			continue
		}

		// Extract tags from the SBOM JSON files
		tags, err := extractSBOMPackages(ctx, layer)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("error extracting tags from sboms.tar: %w", err))
			continue
		}

		for _, tag := range tags {
			result, err := scanWithTrivy(tag, dockerConfigPath, commandExecutor)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("error scanning image with Trivy: %w", err))
				continue
			}
			results = append(results, result)
		}

		break // Only process the first sboms.tar layer
	}

	return results, errs
}

// scanWithTrivy saves the image layer and scans it with Trivy.
//
// Parameters:
//   - ctx: The context for the operation.
//   - imageRef: The reference to the image layer to be scanned.
//   - dockerConfigPath: The path to the Docker config file.
//   - executor: The command executor to use for running Trivy.
//
// Returns:
//   - string: The file path of the Trivy scan result in JSON format.
//   - error: An error if the operation fails.
func scanWithTrivy(imageRef string, dockerConfigPath string,
	commandExecutor types.CommandExecutor) (string, error) {
	err := os.Setenv("DOCKER_CONFIG", dockerConfigPath)
	if err != nil {
		return "", fmt.Errorf("error setting Docker config environment variable: %w", err)
	}

	// Create a temporary file for the Trivy scan results.
	trivyFile, err := os.CreateTemp("", "trivy-*.json")
	if err != nil {
		return "", fmt.Errorf("error creating temporary file for Trivy result: %w", err)
	}
	defer trivyFile.Close()
	// Note: The file cannot be removed here as it is going to be passed up the call stack

	// Check if Trivy exists in the system
	_, _, err = commandExecutor.ExecuteCommand("which", []string{"trivy"}, os.Environ())
	if err != nil {
		return "", fmt.Errorf("trivy is not installed or not found in PATH: %w", err)
	}

	// Run Trivy vulnerability scan on the image layer
	stdout, stderr, err := commandExecutor.ExecuteCommand(
		"trivy",
		[]string{
			"image", "--image-src=remote", imageRef, "--scanners", "vuln",
			"-f", "json", "-o", trivyFile.Name(), "-q",
		},
		os.Environ(),
	)
	if err != nil {
		return "", fmt.Errorf("error running Trivy on image %s: %w\nstdout: %s\nstderr: %s", imageRef, err, stdout, stderr)
	}

	return trivyFile.Name(), nil
}

// extractSBOMPackages extracts tags from JSON files within a tar archive.
//
// Parameters:
//   - ctx: The context for the operation.
//   - layer: The layer to extract tags from.
//
// Returns:
//   - []string: A slice of tags extracted from the layer.
//   - error: An error if the operation fails.
func extractSBOMPackages(ctx context.Context, layer v1.Layer) ([]string, error) {
	if layer == nil {
		return nil, fmt.Errorf("layer cannot be nil")
	}

	layerReader, err := writeLayerToTempFile(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("error writing layer to temp file: %w", err)
	}
	defer layerReader.Close()

	tags, err := readTagsFromLayerFile(ctx, layerReader)
	if err != nil {
		return nil, fmt.Errorf("error reading tags from layer file: %w", err)
	}

	return tags, nil
}

// readTagsFromLayerFile extracts tags from JSON files within a tar archive.
//
// It reads from the provided io.Reader, assuming it to be a tar archive, and searches for JSON files.
// For each JSON file found, it decodes the file into a JSONFile struct and appends the tags found within to a slice.
//
// Parameters:
//   - ctx: The context for the operation. Currently unused.
//   - r: An io.Reader representing the tar archive to read from.
//
// Returns:
//   - []string: A slice of tags extracted from the JSON files within the tar archive.
//   - error: An error if any issues occur during the reading or decoding process.
func readTagsFromLayerFile(_ context.Context, r io.Reader) ([]string, error) {
	tr := tar.NewReader(r)
	var tags []string

	// JSONFile represents the structure of the JSON files within the tar archive.
	type JSONFile struct {
		Source struct {
			Metadata struct {
				Tags []string `json:"tags"`
			} `json:"metadata"`
		} `json:"source"`
	}

	for {
		// Iterate through the contents of the tar archive.
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar file: %w", err)
		}

		// Check if the file is a JSON file based on its name.
		if strings.HasSuffix(header.Name, ".json") {
			var jsonFile JSONFile

			// Decode the JSON file into the JSONFile struct.
			decoder := json.NewDecoder(tr)
			if err := decoder.Decode(&jsonFile); err != nil {
				return nil, fmt.Errorf("error decoding JSON file: %w", err)
			}

			// Append the tags found in the JSON file to the tags slice.
			tags = append(tags, jsonFile.Source.Metadata.Tags...)
		}
	}

	return tags, nil
}

// writeLayerToTempFile writes the provided layer to a temporary file.
//
// Parameters:
//   - ctx: The context for the operation. Currently unused.
//   - layer: The layer to write to the temporary file.
//
// Returns:
//   - io.ReadCloser: A reader pointing to the beginning of the temporary file.
//   - error: An error if any issues occur during the writing process.
func writeLayerToTempFile(_ context.Context, layer v1.Layer) (io.ReadCloser, error) {
	if layer == nil {
		return nil, fmt.Errorf("layer cannot be nil")
	}

	// Create a temporary file with a prefix of "layer-" and a suffix of ".tar"
	tmpFile, err := os.CreateTemp("", "layer-*.tar")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file: %w", err)
	}
	defer func() {
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	// Get the compressed layer reader
	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("error getting layer reader: %w", err)
	}
	defer rc.Close()

	// Copy the layer content to the temporary file
	if _, err := io.Copy(tmpFile, rc); err != nil {
		return nil, fmt.Errorf("error writing layer to temp file: %w", err)
	}

	// Seek to the beginning of the file for reading
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("error seeking temp file: %w", err)
	}

	return tmpFile, nil
}
