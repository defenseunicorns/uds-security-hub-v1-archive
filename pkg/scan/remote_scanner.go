package scan

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// Scanner implements the PackageScanner interface for remote packages.
type Scanner struct {
	logger           types.Logger
	ctx              context.Context
	commandExecutor  types.CommandExecutor
	dockerConfigPath string
	org              string
	packageName      string
	tag              string
	offlineDBPath    string // New field for offline DB path
}

// NewRemotePackageScanner creates a new Scanner for remote packages.
func NewRemotePackageScanner(
	ctx context.Context,
	logger types.Logger,
	dockerConfigPath,
	org,
	packageName,
	tag,
	offlineDBPath string, // New parameter for offline DB path
) types.PackageScanner {
	return &Scanner{
		logger:           logger,
		commandExecutor:  executor.NewCommandExecutor(ctx),
		dockerConfigPath: dockerConfigPath,
		org:              org,
		packageName:      packageName,
		tag:              tag,
		offlineDBPath:    offlineDBPath,
	}
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
func (s *Scanner) ScanResultReader(result types.PackageScannerResult) (types.ScanResultReader, error) {
	file, err := os.Open(result.JSONFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	return &scanResultReader{scanResult: scanResult}, nil
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
func (s *Scanner) ScanZarfPackage(org, packageName, tag string) ([]types.PackageScannerResult, error) {
	s.org = org
	s.packageName = packageName
	s.tag = tag

	return s.Scan(s.ctx)
}

// Scan scans the remote package and returns the scan results.
func (s *Scanner) Scan(ctx context.Context) ([]types.PackageScannerResult, error) {
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
	commandExecutor types.CommandExecutor) ([]types.PackageScannerResult, error) {
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
	commandExecutor types.CommandExecutor) ([]types.PackageScannerResult, error) {
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("error fetching index manifest: %w", err)
	}

	var results []types.PackageScannerResult
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
	commandExecutor types.CommandExecutor) ([]types.PackageScannerResult, error) {
	manifest, err := image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("error fetching image manifest: %w", err)
	}

	var errs error

	tmpDir, err := os.MkdirTemp("", "uds-scan-remote-*")
	if err != nil {
		return nil, err
	}

	pkgOutDir := path.Join(tmpDir, "pkg")

	for i := range manifest.Layers {
		layerDescriptor := &manifest.Layers[i] // Use a pointer to the element
		title, ok := layerDescriptor.Annotations["org.opencontainers.image.title"]
		if !ok {
			continue
		}

		// extract all layers into their original filesystem location
		layer, err := image.LayerByDigest(layerDescriptor.Digest)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to fetch LayerByDigest: %w", err))
			continue
		}

		r, err := layer.Compressed()
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to fetch layer: %w", err))
			continue
		}

		err = os.MkdirAll(path.Join(pkgOutDir, path.Dir(title)), 0o700)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to mkdir for extracted layer: %w", err))
			continue
		}

		f, err := os.Create(path.Join(pkgOutDir, title))
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to create output file: %w", err))
			continue
		}

		_, err = io.Copy(f, r)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to write layer to disk: %w", err))
			continue
		}

		err = f.Close()
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to close file after writing: %w", err))
			continue
		}
	}

	images, err := extractAllImages(tmpDir, pkgOutDir, s.logger, s.commandExecutor)
	if err != nil {
		return nil, err
	}

	var results []types.PackageScannerResult
	for _, image := range images {
		result, err := scanWithTrivy(image, dockerConfigPath, s.offlineDBPath, s.commandExecutor)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to scanWithTrivy: %w", err))
			continue
		}
		results = append(results, *result)
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
//   - offlineDBPath: The path to the offline DB to use for the scan.
//
// Returns:
//   - string: The file path of the Trivy scan result in JSON format.
//   - error: An error if the operation fails.
func scanWithTrivy(imageRef imageRef, dockerConfigPath string, offlineDBPath string,
	commandExecutor types.CommandExecutor) (*types.PackageScannerResult, error) {
	const trivyDBFileName = "db/trivy.db"
	const metadataFileName = "db/metadata.json"

	if dockerConfigPath != "" {
		err := os.Setenv("DOCKER_CONFIG", dockerConfigPath)
		if err != nil {
			return nil, fmt.Errorf("error setting Docker config environment variable: %w", err)
		}
		defer os.Unsetenv("DOCKER_CONFIG")
	}

	if offlineDBPath != "" {
		trivyDBPath := filepath.Join(offlineDBPath, trivyDBFileName)
		metadataPath := filepath.Join(offlineDBPath, metadataFileName)

		if _, err := os.Stat(trivyDBPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("trivy.db does not exist in the offline DB path: %s", offlineDBPath)
		}

		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("metadata.json does not exist in the offline DB path: %s", offlineDBPath)
		}
	}

	// Create a temporary file for the Trivy scan results.
	trivyFile, err := os.CreateTemp("", "trivy-*.json")
	if err != nil {
		return nil, fmt.Errorf("error creating temporary file for Trivy result: %w", err)
	}
	defer trivyFile.Close()
	// Note: The file cannot be removed here as it is going to be passed up the call stack

	// Check if Trivy exists in the system
	_, _, err = commandExecutor.ExecuteCommand("which", []string{"trivy"}, os.Environ())
	if err != nil {
		return nil, fmt.Errorf("trivy is not installed or not found in PATH: %w", err)
	}

	var args []string
	args = append(args, imageRef.TrivyCommand()...)
	args = append(args,
		[]string{"--scanners", "vuln", "-f", "json", "-o", trivyFile.Name()}...,
	)
	if offlineDBPath != "" {
		args = append(args,
			"--skip-db-update", "--skip-java-db-update", "--offline-scan",
			"--skip-check-update", "--cache-dir", offlineDBPath)
	}
	stdout, stderr, err := commandExecutor.ExecuteCommand(
		"trivy",
		args,
		os.Environ(),
	)
	if err != nil {
		return nil, fmt.Errorf("error running Trivy on image %s: %w\nstdout: %s\nstderr: %s args: %s",
			imageRef, err, stdout, stderr, args)
	}

	result := &types.PackageScannerResult{
		JSONFilePath: trivyFile.Name(),
	}

	if override, ok := imageRef.(ArtifactNameOverride); ok {
		result.ArtifactNameOverride = override.ArtifactNameOverride()
	}

	return result, nil
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
