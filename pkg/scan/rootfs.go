package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/zap"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func extractZarfPackageToTmpDir(
	tmpDir string,
	tarBytes []byte,
	command types.CommandExecutor,
) (string, error) {
	pkgOutDir := path.Join(tmpDir, "pkg")

	tarPkgOnDisk := path.Join(tmpDir, "pkg.tar")
	err := os.WriteFile(tarPkgOnDisk, tarBytes, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to write tar file: %w", err)
	}

	err = os.Mkdir(pkgOutDir, 0o700)
	if err != nil {
		return "", fmt.Errorf("failed to create output pkg dir: %w", err)
	}

	_, _, err = command.ExecuteCommand(
		"tar",
		[]string{"-xf", tarPkgOnDisk, "-C", pkgOutDir},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to untar package: %w", err)
	}

	return pkgOutDir, nil
}

func unmarshalJSONFromFilename(filename string, out interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filename, err)
	}

	err = json.NewDecoder(f).Decode(out)
	if err != nil {
		return fmt.Errorf("failed to decode %s: %w", filename, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("failed to close file %s: %w", filename, err)
	}

	return nil
}

// extractAllImagesFromOCIDirectory reads from the images/index.json file and extracts
// all images from that IndexManifest
func extractAllImagesFromOCIDirectory(
	outputDir string,
	pkgRoot string,
	logger types.Logger,
	command types.CommandExecutor,
) ([]imageRef, error) {
	var indexManifest v1.IndexManifest
	err := unmarshalJSONFromFilename(path.Join(pkgRoot, "images/index.json"), &indexManifest)
	if err != nil {
		return nil, err
	}

	type ImageToScan struct {
		Manifest *v1.Manifest
		Name     string
	}

	var imagesToScan []ImageToScan

	for i := range indexManifest.Manifests {
		name := indexManifest.Manifests[i].Annotations["org.opencontainers.image.base.name"]
		digest := indexManifest.Manifests[i].Digest

		if !scannableImage(name) {
			continue
		}

		var manifest v1.Manifest
		manifestLocation := path.Join(pkgRoot, "images", "blobs", digest.Algorithm, digest.Hex)
		err := unmarshalJSONFromFilename(manifestLocation, &manifest)
		if err != nil {
			return nil, err
		}

		imagesToScan = append(imagesToScan, ImageToScan{
			Name:     name,
			Manifest: &manifest,
		})
	}

	var results []imageRef
	for _, image := range imagesToScan {
		imageRootFS := path.Join(outputDir, replacePathChars(image.Name))
		if err := os.Mkdir(imageRootFS, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create dir for image %s: %w", image.Name, err)
		}
		for i := range image.Manifest.Layers {
			digest := image.Manifest.Layers[i].Digest.Hex
			layerBlob := path.Join(pkgRoot, "images", "blobs", "sha256", digest)
			_, stderr, err := command.ExecuteCommand(
				"tar",
				[]string{"--exclude=dev/*", "-zvxf", layerBlob, "-C", imageRootFS},
				nil,
			)
			if err != nil {
				logger.Warn(
					"error occurred while extracting layer",
					zap.String("imageName", image.Name),
					zap.String("digest", digest),
					zap.String("stderr", stderr),
					zap.Error(err),
				)
			}

			// add read and write permissions to the user or the subsequent layers, the trivy scan,
			// and the cleanup will fail
			_, _, err = command.ExecuteCommand(
				"chmod",
				[]string{"-R", "u+rw", imageRootFS},
				nil,
			)
			if err != nil {
				logger.Warn(
					"unable to ensure proper permissions on extracted files",
					zap.String("imageName", image.Name),
					zap.Error(err),
				)
			}
		}
		results = append(results, rootfsRef{
			ArtifactName: image.Name,
			RootFSDir:    imageRootFS,
		})
	}

	return results, nil
}

type cleanupFunc func()

func ExtractRootFsFromTarFilePath(
	logger types.Logger,
	tarFilePath string,
	command types.CommandExecutor,
) ([]imageRef, cleanupFunc, error) {
	f, err := os.Open(tarFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open tar: %w", err)
	}

	r, err := zstd.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unzstd tar: %w", err)
	}

	tarBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read tar: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "uds-local-scan-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	pkgOutDir, err := extractZarfPackageToTmpDir(tmpDir, tarBytes, command)
	if err != nil {
		return nil, nil, err
	}

	results, err := extractAllImagesFromOCIDirectory(tmpDir, pkgOutDir, logger, command)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return results, cleanup, nil
}

// replacePathChars replaces characters in a image name that will cause issues in filesystems.
func replacePathChars(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

// scannableImage returns true if the image should be scanned.
// it's mainly used to skip *.att and *.sig files which do not represent container images
// that can be scanned.
func scannableImage(name string) bool {
	if strings.HasSuffix(name, ".att") || strings.HasSuffix(name, ".sig") {
		return false
	}

	return true
}
