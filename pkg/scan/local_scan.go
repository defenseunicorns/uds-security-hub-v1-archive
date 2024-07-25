package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/defenseunicorns/uds-security-hub/internal/executor"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type imageRef interface {
	Flags() []string
}

type remoteImageRef struct {
	ImageRef string
}

func (r *remoteImageRef) Flags() []string {
	return []string{"image", "--remote", r.ImageRef}
}

type localImageRef struct {
	Name      string
	RootFSDir string
}

func (l *localImageRef) Flags() []string {
	return []string{"rootfs", l.RootFSDir, "--offline-scan"}
}

// LocalPackageScanner is a struct that holds the logger and paths for docker configuration and package.
type LocalPackageScanner struct {
	logger           types.Logger
	dockerConfigPath string
	packagePath      string
	offlineDBPath    string // New field for offline DB path
}

// Scan scans the package and returns the scan results which are trivy scan results in json format.
// Parameters:
// - ctx: the context to use for the scan.
// Returns:
// - []string: the scan results which are trivy scan results in json format.
// - error: an error if the scan fails.
func (lps *LocalPackageScanner) Scan(ctx context.Context) ([]string, error) {
	if lps.packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	commandExecutor := executor.NewCommandExecutor(ctx)
	images, err := ExtractImagesFromTar(lps.packagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from tar: %w", err)
	}
	var scanResults []string
	for _, image := range images {
		scanResult, err := scanWithTrivy(image, lps.dockerConfigPath,
			lps.offlineDBPath, commandExecutor)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image %s: %w", image, err)
		}
		scanResults = append(scanResults, scanResult)
	}
	return scanResults, nil
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
func NewLocalPackageScanner(logger types.Logger, dockerConfigPath,
	packagePath, offlineDBPath string) (types.PackageScanner, error) {
	if packagePath == "" {
		return nil, fmt.Errorf("packagePath cannot be empty")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	return &LocalPackageScanner{
		logger:           logger,
		dockerConfigPath: dockerConfigPath,
		packagePath:      packagePath,
		offlineDBPath:    offlineDBPath,
	}, nil
}

// ImageManifest represents the structure of the image manifest in the index.json file.
type ImageManifest struct {
	Annotations struct {
		BaseName string `json:"org.opencontainers.image.base.name"`
	} `json:"annotations"`
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

// ImageIndex represents the structure of the index.json file.
type ImageIndex struct {
	MediaType     string          `json:"mediaType"`
	Manifests     []ImageManifest `json:"manifests"`
	SchemaVersion int             `json:"schemaVersion"`
}

type blob struct {
	Digest string
	Data   []byte `json:"-"`
}
type ImageLayerManifest struct {
	SchemaVersion int                       `json:"schemaVersion"`
	MediaType     string                    `json:"mediaType"`
	Config        ImageLayerManifestConfig  `json:"config"`
	Layers        []ImageLayerManifestLayer `json:"layers"`
}
type ImageLayerManifestConfig struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}
type ImageLayerManifestLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

// ExtractImagesFromTar extracts images from the tar archive and returns names of the container images.
// Parameters:
// - tarFilePath: the path to the tar archive to extract the images from.
// Returns:
// - []string: the names of the container images.
// - error: an error if the extraction fails.
func ExtractImagesFromTar(tarFilePath string) ([]*localImageRef, error) {
	const indexJSONFileName = "images/index.json"

	if tarFilePath == "" {
		return nil, fmt.Errorf("tarFilePath cannot be empty")
	}

	if _, err := os.Stat(tarFilePath); err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
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

	tarReader := tar.NewReader(zstdReader)

	var index ImageIndex

	blobData := make(map[string]*blob)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == indexJSONFileName {
			if err := json.NewDecoder(tarReader).Decode(&index); err != nil {
				return nil, fmt.Errorf("failed to decode index.json: %w", err)
			}
			continue
		}

		imageDirPrefix := "images/blobs/sha256/"
		if strings.Contains(header.Name, imageDirPrefix) {
			name := strings.TrimPrefix(header.Name, imageDirPrefix)
			if name != "" {
				data, err := io.ReadAll(tarReader)
				if err != nil {
					log.Printf("issue with reading: %s", err)
				}
				blobData[name] = &blob{Digest: name, Data: data}
				continue
			}
		}
	}

	var results []*localImageRef

	for _, manifest := range index.Manifests {
		imageName := manifest.Annotations.BaseName
		if imageName != "" && !strings.HasSuffix(imageName, ".att") && !strings.HasSuffix(imageName, ".sig") {
			var imageLayerManifest ImageLayerManifest
			digest := strings.TrimPrefix(manifest.Digest, "sha256:")
			json.NewDecoder(bytes.NewReader(blobData[digest].Data)).Decode(&imageLayerManifest)

			dir, err := os.MkdirTemp("", "zarf-image-*")
			if err != nil {
				return nil, err
			}

			for _, layer := range imageLayerManifest.Layers {
				digest := strings.TrimPrefix(layer.Digest, "sha256:")
				zipReader, err := gzip.NewReader(bytes.NewReader(blobData[digest].Data))
				if err != nil {
					return nil, err
				}
				tReader := tar.NewReader(zipReader)

				for {
					header, err := tReader.Next()
					if err == io.EOF {
						break
					}

					if err != nil {
						return nil, err
					}

					target := filepath.Join(dir, header.Name)

					switch header.Typeflag {

					// if its a dir and it doesn't exist create it
					case tar.TypeDir:
						if _, err := os.Stat(target); err != nil {
							if err := os.MkdirAll(target, 0755); err != nil {
								return nil, err
							}
						}

					// if it's a file create it
					case tar.TypeReg:
						f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
						if err != nil {
							return nil, err
						}

						// copy over contents
						if _, err := io.Copy(f, tReader); err != nil {
							return nil, err
						}

						// manually close here after each file operation; defering would cause each file close
						// to wait until all operations have completed.
						f.Close()
					}
				}
			}

			results = append(results, &localImageRef{Name: manifest.Annotations.BaseName, RootFSDir: dir})
		}

	}

	return results, nil
}

// ScanResultReader reads the scan result from the json file and returns the scan result.
// Parameters:
// - jsonFilePath: the path to the json file to read the scan result from.
// Returns:
// - types.ScanResultReader: the scan result.
// - error: an error if the reading fails.
func (lps *LocalPackageScanner) ScanResultReader(jsonFilePath string) (types.ScanResultReader, error) {
	if jsonFilePath == "" {
		return nil, fmt.Errorf("jsonFilePath cannot be empty")
	}
	if _, err := os.Stat(jsonFilePath); err != nil {
		return nil, fmt.Errorf("failed to open JSON file: %w", err)
	}
	file, err := os.Open(jsonFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JSON file: %w", err)
	}
	defer file.Close()

	var scanResult types.ScanResult
	if err := json.NewDecoder(file).Decode(&scanResult); err != nil {
		return nil, fmt.Errorf("failed to decode JSON file: %w", err)
	}

	return &localScanResultReader{scanResult: scanResult}, nil
}

// localScanResultReader is a concrete implementation of the ScanResultReader interface.
type localScanResultReader struct {
	scanResult types.ScanResult
}

// GetArtifactName returns the artifact name of the scan result.
func (lsr *localScanResultReader) GetArtifactName() string {
	return lsr.scanResult.ArtifactName
}

// GetVulnerabilities returns the vulnerabilities of the scan result.
func (lsr *localScanResultReader) GetVulnerabilities() []types.VulnerabilityInfo {
	if len(lsr.scanResult.Results) == 0 {
		return []types.VulnerabilityInfo{}
	}
	return lsr.scanResult.Results[0].Vulnerabilities
}

// GetResultsAsCSV returns the scan result as a CSV string.
func (lsr *localScanResultReader) GetResultsAsCSV() string {
	var sb strings.Builder
	sb.WriteString("\"ArtifactName\",\"VulnerabilityID\",\"PkgName\",\"InstalledVersion\",\"FixedVersion\",\"Severity\",\"Description\"\n") //nolint:lll

	vulnerabilities := lsr.GetVulnerabilities()
	for _, vuln := range vulnerabilities {
		sb.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			lsr.GetArtifactName(),
			vuln.VulnerabilityID,
			vuln.PkgName,
			vuln.InstalledVersion,
			vuln.FixedVersion,
			vuln.Severity,
			vuln.Description))
	}
	return sb.String()
}
