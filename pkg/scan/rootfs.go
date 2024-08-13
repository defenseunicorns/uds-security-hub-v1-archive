package scan

import (
	"bytes"
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

type cleanupFunc func() error

func ExtractRootFS(logger types.Logger, tarFilePath string, command types.CommandExecutor) ([]imageRef, cleanupFunc, error) {
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

	files, err := extractFilesFromTar(bytes.NewReader(tarBytes), "images/index.json")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract index.json: %w", err)
	}

	var imagesIndex v1.IndexManifest
	if err := json.Unmarshal(files["images/index.json"], &imagesIndex); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal index.json: %w", err)
	}

	imageNameToManifestFile := make(map[string]string)
	var manifestFilesToExtract []string
	for i := range imagesIndex.Manifests {
		digest := imagesIndex.Manifests[i].Digest.Hex
		name := imagesIndex.Manifests[i].Annotations["org.opencontainers.image.base.name"]

		if !scannableImage(name) {
			continue
		}

		layerLocation := fmt.Sprintf("images/blobs/sha256/%s", digest)
		imageNameToManifestFile[name] = layerLocation
		manifestFilesToExtract = append(manifestFilesToExtract, layerLocation)
	}

	extractedManifests, err := extractFilesFromTar(bytes.NewReader(tarBytes), manifestFilesToExtract...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract image manifests: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "uds-local-scan-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create tmp dir: %w", err)
	}

	tarPkgOnDisk := path.Join(tmpDir, "pkg.tar")
	if err := os.WriteFile(tarPkgOnDisk, tarBytes, 0o600); err != nil {
		return nil, nil, fmt.Errorf("failed to write tar file: %w", err)
	}

	pkgOutDir := path.Join(tmpDir, "pkg")
	if err := os.Mkdir(pkgOutDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("failed to create output pkg dir: %w", err)
	}
	_, _, err = command.ExecuteCommand(
		"tar",
		[]string{"-xf", tarPkgOnDisk, "-C", pkgOutDir},
		nil,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to untar package: %w", err)
	}

	imageNameToParsedManifest := make(map[string]v1.Manifest)
	for imageName, manifestFileName := range imageNameToManifestFile {
		var packagedManifest v1.Manifest
		err := json.Unmarshal(extractedManifests[manifestFileName], &packagedManifest)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal image manifest: %w", err)
		}
		imageNameToParsedManifest[imageName] = packagedManifest
	}

	var results []imageRef

	for imageName, manifest := range imageNameToParsedManifest {
		imageRootFS := path.Join(tmpDir, replacePathChars(imageName))
		if err := os.Mkdir(imageRootFS, 0o700); err != nil {
			return nil, nil, fmt.Errorf("failed to create dir for image %s: %w", imageName, err)
		}
		for i := range manifest.Layers {
			digest := manifest.Layers[i].Digest.Hex
			layerBlob := path.Join(pkgOutDir, "images", "blobs", "sha256", digest)
			_, stderr, err := command.ExecuteCommand(
				"tar",
				[]string{"--exclude=dev/*", "-zvxf", layerBlob, "-C", imageRootFS},
				nil,
			)
			if err != nil {
				logger.Warn(
					"error occurred while extracting layer",
					zap.String("imageName", imageName),
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
					zap.String("imageName", imageName),
					zap.Error(err),
				)
			}
		}
		results = append(results, rootfsRef{
			ArtifactName: imageName,
			RootFSDir:    imageRootFS,
		})
	}

	cleanup := func() error {
		return os.RemoveAll(tmpDir)
	}

	return results, cleanup, nil
}

func replacePathChars(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

func scannableImage(name string) bool {
	if strings.HasSuffix(name, ".att") || strings.HasSuffix(name, ".sig") {
		return false
	}

	return true
}
