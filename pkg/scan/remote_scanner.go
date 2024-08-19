package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
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
	sbom             bool
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
	sbom bool,
) types.PackageScanner {
	return &Scanner{
		logger:           logger,
		commandExecutor:  executor.NewCommandExecutor(ctx),
		dockerConfigPath: dockerConfigPath,
		org:              org,
		packageName:      packageName,
		tag:              tag,
		offlineDBPath:    offlineDBPath,
		sbom:             sbom,
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

	return &scanResultReader{ArtifactNameOverride: result.ArtifactNameOverride, scanResult: scanResult}, nil
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

	commandExecutor := executor.NewCommandExecutor(ctx)
	imageRef := fmt.Sprintf("ghcr.io/%s/%s:%s", s.org, s.packageName, s.tag)

	results, err := s.scanImageAndProcessResults(ctx, imageRef, s.dockerConfigPath, commandExecutor)
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

	desiredPlatform := "amd64"

	var scannables []trivyScannable
	if s.sbom {
		sbomScannables, err := s.processSBOMScannables(ctx, idx, desiredPlatform)
		if err != nil {
			return nil, fmt.Errorf("failed to process SBOM scannables: %w", err)
		}
		scannables = sbomScannables
	} else {
		rootfsScannables, err := s.processRootfsScannables(idx, commandExecutor, desiredPlatform)
		if err != nil {
			return nil, fmt.Errorf("failed to process rootfs scannables: %w", err)
		}
		scannables = rootfsScannables
	}

	var errs error
	var results []types.PackageScannerResult
	for _, image := range scannables {
		result, err := scanWithTrivy(image, dockerConfigPath, s.offlineDBPath, commandExecutor)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to scanWithTrivy: %w", err))
			continue
		}
		results = append(results, *result)
	}

	if errs != nil {
		return nil, errs
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
	err := os.Setenv("DOCKER_CONFIG", s.dockerConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to set DOCKER_CONFIG env var: %w", err)
	}
	defer os.Unsetenv("DOCKER_CONFIG")

	idx, err := remote.Index(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image index: %w", err)
	}
	return idx, nil
}

func (s *Scanner) processSBOMScannables(
	ctx context.Context,
	idx v1.ImageIndex,
	desiredPlatform string,
) ([]trivyScannable, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image manifest: %w", err)

	}

	platformDigest := findDesiredPlatform(manifest.Manifests, desiredPlatform)
	if platformDigest == nil {
		return nil, fmt.Errorf("failed to find desired platform: %s", desiredPlatform)
	}

	platformImage, err := idx.Image(*platformDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to read platform %s image: %w", desiredPlatform, err)
	}

	platformManifest, err := platformImage.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get platform %s manifest: %w", desiredPlatform, err)
	}

	for i := range platformManifest.Layers {
		layerDescriptor := platformManifest.Layers[i]
		if layerDescriptor.Annotations["org.opencontainers.image.title"] == "sboms.tar" {
			layer, err := platformImage.LayerByDigest(layerDescriptor.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to get sboms.tar layer for platform %s: %w", desiredPlatform, err)
			}
			// do something with it
			return extractSBOMPackages(ctx, layer)
		}
	}

	return nil, fmt.Errorf("failed to find an sboms.tar layer")
}

func (s *Scanner) processRootfsScannables(
	idx v1.ImageIndex,
	commandExecutor types.CommandExecutor,
	desiredPlatform string,
) ([]trivyScannable, error) {
	tmpDir, err := os.MkdirTemp("", "uds-remote-oci-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	// mirror the structure from a zarf package extract
	pkgOutDir := path.Join(tmpDir, "pkg")
	imagesDir := path.Join(pkgOutDir, "images")
	err = os.MkdirAll(imagesDir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("failed to create output directories: %w", err)
	}

	err = writeImageIndexToLocalLayoutAndReplaceIndexJSONWithDesiredPlatform(idx, imagesDir, desiredPlatform)
	if err != nil {
		return nil, fmt.Errorf("failed to create local oci image directory: %w", err)
	}

	images, err := extractAllImagesFromOCIDirectory(tmpDir, pkgOutDir, s.logger, commandExecutor)
	if err != nil {
		return nil, fmt.Errorf("failed to extractAllImagesFromOCIDirectory: %w", err)
	}

	return images, nil
}

// writeImageIndexToLocalLayoutAndReplaceIndexJSONWithDesiredPlatform takes in an
// ImageIndex and writes to imagesDir. It then reads through the ImageManifest and finds
// the first manifest with the desired platform. It will replace the index.json with the
// index.json from that desired platform.
//
// The local filesystem will include all layers from both platforms, but when used with
// other scanning code it will ignore the layers unrelated to the platform the index.json
// will only be for the desired platform.
func writeImageIndexToLocalLayoutAndReplaceIndexJSONWithDesiredPlatform(
	idx v1.ImageIndex,
	imagesDir string,
	desiredPlatform string,
) error {
	ociPath, err := layout.Write(imagesDir, idx)
	if err != nil {
		return fmt.Errorf("failed to write ImageIndex to layout: %w", err)
	}

	// now we can use the local copy for querying for the specific index.json
	ociPathIndex, err := ociPath.ImageIndex()
	if err != nil {
		return fmt.Errorf("failed to read ImageIndex from local copy: %w", err)
	}

	manifest, err := ociPathIndex.IndexManifest()
	if err != nil {
		return fmt.Errorf("failed to read IndexManifest from local copy: %w", err)
	}

	desiredPlatformDigest := findDesiredPlatform(manifest.Manifests, desiredPlatform)
	if desiredPlatformDigest == nil {
		return fmt.Errorf("failed to find %s manifest", desiredPlatform)
	}

	platformManifestBytes, err := ociPath.Bytes(*desiredPlatformDigest)
	if err != nil {
		return fmt.Errorf("failed to read %s manifest file: %w", desiredPlatform, err)
	}

	var platformManifest v1.Manifest
	if err := json.Unmarshal(platformManifestBytes, &platformManifest); err != nil {
		return fmt.Errorf("failed to json decode %s manifest: %w", desiredPlatform, err)
	}

	platformIndexJSON := findImagesIndexJSON(platformManifest.Layers)
	if platformIndexJSON == nil {
		return fmt.Errorf("failed to find %s images/index.json", desiredPlatform)
	}

	platformIndexJSONBytes, err := ociPath.Bytes(*platformIndexJSON)
	if err != nil {
		return fmt.Errorf("failed to read %s images/index.json bytes", desiredPlatform)
	}

	// overwrite the existing index.json we found with the platform specific one
	err = os.WriteFile(path.Join(imagesDir, "index.json"), platformIndexJSONBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to replace index.json: %w", err)
	}

	return nil
}

// findDesiredPlatform returns the v1.Hash for the desiredPlatform, if found.
func findDesiredPlatform(manifests []v1.Descriptor, desiredPlatform string) *v1.Hash {
	for i := range manifests {
		if manifests[i].Platform.Architecture == desiredPlatform {
			return &manifests[i].Digest
		}
	}

	return nil
}

// findImagesIndexJSON returns the v1.Hash of the layer with the correct annotation, if found.
func findImagesIndexJSON(layers []v1.Descriptor) *v1.Hash {
	for i := range layers {
		if layers[i].Annotations["org.opencontainers.image.title"] == "images/index.json" {
			return &layers[i].Digest
		}
	}

	return nil
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
func scanWithTrivy(imageRef trivyScannable, dockerConfigPath string, offlineDBPath string,
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
func extractSBOMPackages(ctx context.Context, layer v1.Layer) ([]trivyScannable, error) {
	if layer == nil {
		return nil, fmt.Errorf("layer cannot be nil")
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("failed to read uncompressed layer: %w", err)
	}

	return extractSBOMImageRefsFromReader(r)
}
