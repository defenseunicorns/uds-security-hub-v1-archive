package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/klauspost/compress/zstd"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

const (
	SbomFilename = "sboms.tar"
)

type imageRef interface {
	TrivyCommand() []string
}

type remoteImageRef struct {
	ImageRef string
}

func (r *remoteImageRef) TrivyCommand() []string {
	return []string{"image", "--image-src=remote", r.ImageRef}
}

type cyclonedxSbomRef struct {
	ArtifactName string
	SBOMFile     string
}

func (s *cyclonedxSbomRef) TrivyCommand() []string {
	return []string{"sbom", s.SBOMFile}
}

type rootfsRef struct {
	ArtifactName string
	RootFSDir    string
}

func (r *rootfsRef) TrivyCommand() []string {
	return []string{"rootf", r.RootFSDir}
}

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

func extractSBOMTarFromZarfPackage(tarFilePath string) ([]byte, error) {
	file, err := os.Open(tarFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	defer file.Close()

	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader: %w", err)
	}
	defer zstdReader.Close()
	files, err := extractFilesFromTar(zstdReader, SbomFilename)
	if err != nil {
		return nil, err
	}

	return files[SbomFilename], nil
}

func extractArtifactInformationFromSBOM(r io.Reader) string {
	type SyftSbomHeader struct {
		Source struct {
			Metadata struct {
				Tags []string `json:"tags"`
			} `json:"metadata"`
		} `json:"source"`
	}

	var sbomHeader SyftSbomHeader

	err := json.NewDecoder(r).Decode(&sbomHeader)
	if err != nil {
		return ""
	}

	if len(sbomHeader.Source.Metadata.Tags) == 0 {
		return ""
	}

	return sbomHeader.Source.Metadata.Tags[0]
}

func convertToCyclonedxFormat(header *tar.Header, r io.Reader, outputDir string) (*cyclonedxSbomRef, error) {
	cyclonedxEncoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create cyclonedx encoder: %w", err)
	}

	sbomData, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read sbom from tar for %q: %w", header.Name, err)
	}

	artifactName := extractArtifactInformationFromSBOM(bytes.NewReader(sbomData))
	if artifactName == "" {
		// default to the filename if we were unable to extract anything meaningful
		artifactName = header.Name
	}

	sbom, _, _, err := format.Decode(bytes.NewReader(sbomData))
	if err != nil {
		return nil, fmt.Errorf("failed to convert sbom format for %q: %w", header.Name, err)
	}

	cyclonedxBytes, err := format.Encode(*sbom, cyclonedxEncoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode cyclonnedx format for %q: %w", header.Name, err)
	}

	// use a sha256 for the filename in the tar to avoid any security issues with malformed tar
	sbomSha256 := sha256.Sum256(cyclonedxBytes)
	cyclonedxSBOMFilename := path.Join(outputDir, fmt.Sprintf("%x", sbomSha256))
	if err := os.WriteFile(cyclonedxSBOMFilename, cyclonedxBytes, header.FileInfo().Mode().Perm()); err != nil {
		return nil, fmt.Errorf("failed to write new cyclonnedx file for %q: %w", header.Name, err)
	}

	return &cyclonedxSbomRef{
		ArtifactName: artifactName,
		SBOMFile:     cyclonedxSBOMFilename,
	}, nil
}

func extractSBOMImageRefsFromReader(r io.Reader) ([]*cyclonedxSbomRef, error) {
	tmp, err := os.MkdirTemp("", "zarf-sbom-spdx-files-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	var results []*cyclonedxSbomRef

	sbomTarReader := tar.NewReader(r)
	for {
		header, err := sbomTarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read header in sbom tar: %w", err)
		}

		if strings.HasSuffix(header.Name, ".json") {
			sbomImageRef, err := convertToCyclonedxFormat(header, sbomTarReader, tmp)
			if err != nil {
				return nil, err
			}
			results = append(results, sbomImageRef)
		}
	}

	return results, nil
}

func scannableImage(name string) bool {
	if strings.HasSuffix(name, ".att") || strings.HasSuffix(name, ".sig") {
		return false
	}

	return true
}

func replacePathChars(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

type ExtractRootFSResult struct {
	RootPath string
	Refs     []rootfsRef
}

func (e *ExtractRootFSResult) Close() error {
	return os.RemoveAll(e.RootPath)
}

func ExtractRootFS(tarFilePath string, command types.CommandExecutor) (*ExtractRootFSResult, error) {
	f, err := os.Open(tarFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar: %w", err)
	}

	r, err := zstd.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to unzstd tar: %w", err)
	}

	tarBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read tar: %w", err)
	}

	files, err := extractFilesFromTar(bytes.NewReader(tarBytes), "images/index.json")
	if err != nil {
		return nil, fmt.Errorf("failed to extract index.json: %w", err)
	}

	var imagesIndex v1.IndexManifest
	if err := json.Unmarshal(files["images/index.json"], &imagesIndex); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index.json: %w", err)
	}

	imageNameToManifestFile := make(map[string]string)
	var manifestFilesToExtract []string
	for _, manifest := range imagesIndex.Manifests {
		digest := manifest.Digest.Hex
		name := manifest.Annotations["org.opencontainers.image.base.name"]

		if !scannableImage(name) {
			continue
		}

		layerLocation := fmt.Sprintf("images/blobs/sha256/%s", digest)
		imageNameToManifestFile[name] = layerLocation
		manifestFilesToExtract = append(manifestFilesToExtract, layerLocation)
	}

	extractedManifests, err := extractFilesFromTar(bytes.NewReader(tarBytes), manifestFilesToExtract...)
	if err != nil {
		return nil, fmt.Errorf("failed to extract image manifests: %w", err)
	}

	imageNameToParsedManifest := make(map[string]v1.Manifest)
	for imageName, manifestFileName := range imageNameToManifestFile {
		var packagedManifest v1.Manifest
		err := json.Unmarshal(extractedManifests[manifestFileName], &packagedManifest)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal image manifest: %w", err)
		}
		imageNameToParsedManifest[imageName] = packagedManifest
	}

	tmpDir, err := os.MkdirTemp("", "uds-local-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	tarPkgOnDisk := path.Join(tmpDir, "pkg.tar")
	if err := os.WriteFile(tarPkgOnDisk, tarBytes, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write tar file: %w", err)
	}

	pkgOutDir := path.Join(tmpDir, "pkg")
	if err := os.Mkdir(pkgOutDir, 0o700); err != nil {
		return nil, err
	}
	_, _, err = command.ExecuteCommand(
		"tar",
		[]string{"-xf", tarPkgOnDisk, "-C", pkgOutDir},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to untar package: %w", err)
	}

	var results []rootfsRef

	for imageName, manifest := range imageNameToParsedManifest {
		imageRootFS := path.Join(tmpDir, replacePathChars(imageName))
		if err := os.Mkdir(imageRootFS, 0o700); err != nil {
			return nil, err
		}
		for _, layer := range manifest.Layers {
			layerBlob := path.Join(pkgOutDir, "images", "blobs", "sha256", layer.Digest.Hex)
			_, _, err := command.ExecuteCommand(
				"tar",
				[]string{"-zxf", layerBlob, "-C", imageRootFS},
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to untar package imageRootFS=%s imageName=%s blob=%s: %w", imageRootFS, imageName, layer.Digest.Hex, err)
			}
		}
		results = append(results, rootfsRef{
			ArtifactName: imageName,
			RootFSDir:    imageRootFS,
		})
	}

	return &ExtractRootFSResult{RootPath: tmpDir, Refs: results}, nil
}

// ExtractSBOMsFromTar extracts images from the tar archive and returns names of the container images.
// Parameters:
// - tarFilePath: the path to the tar archive to extract the images from.
// Returns:
// - []sbomImageRef: references to images and their sboms.
// - error: an error if the extraction fails.
func ExtractSBOMsFromTar(tarFilePath string) ([]*cyclonedxSbomRef, error) {
	sbomTar, err := extractSBOMTarFromZarfPackage(tarFilePath)
	if err != nil {
		return nil, err
	}

	return extractSBOMImageRefsFromReader(bytes.NewReader(sbomTar))
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
	sbomFiles, err := ExtractSBOMsFromTar(lps.packagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from tar: %w", err)
	}
	var scanResults []types.PackageScannerResult
	for _, sbom := range sbomFiles {
		scanResult, err := scanWithTrivy(sbom, "", lps.offlineDBPath, commandExecutor)
		if err != nil {
			return nil, fmt.Errorf("failed to scan sbom %s: %w", sbom.SBOMFile, err)
		}
		scanResults = append(scanResults, types.PackageScannerResult{
			ArtifactNameOverride: sbom.ArtifactName,
			JSONFilePath:         scanResult,
		})
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
