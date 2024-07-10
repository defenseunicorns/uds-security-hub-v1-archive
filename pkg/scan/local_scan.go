package scan

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// LocalPackageScanner is a struct that holds the logger and paths for docker configuration and package.
type LocalPackageScanner struct {
	logger           types.Logger
	dockerConfigPath string
	packagePath      string
}

// NewLocalPackageScanner creates a new LocalPackageScanner instance.
func NewLocalPackageScanner(logger types.Logger, dockerConfigPath, packagePath string) (*LocalPackageScanner, error) {
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

// ExtractImagesFromTar extracts images from the tar archive and returns their names.
func ExtractImagesFromTar(tarFilePath string) ([]string, error) {
	file, err := os.Open(tarFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	defer file.Close()

	// Create a zstd reader
	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader: %w", err)
	}
	defer zstdReader.Close()

	// Use tar.NewReader on the zstd reader
	tarReader := tar.NewReader(zstdReader)

	var index ImageIndex
	var imageNames []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == "images/index.json" {
			if err := json.NewDecoder(tarReader).Decode(&index); err != nil {
				return nil, fmt.Errorf("failed to decode index.json: %w", err)
			}
			break // We only need the index.json file
		}
	}

	for _, manifest := range index.Manifests {
		imageName := manifest.Annotations.BaseName
		if imageName != "" {
			imageNames = append(imageNames, imageName)
		}
	}

	return imageNames, nil
}
