package scan

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/klauspost/compress/zstd"
)

// Sanitize archive file pathing from "G305: Zip Slip vulnerability".
func sanitizeArchivePath(dir, filename string) (v string, err error) {
	v = filepath.Join(dir, filename)
	if strings.HasPrefix(v, filepath.Clean(dir)) {
		return v, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", filename)
}

func extractTarToDir(outDir string, r io.Reader) error {
	tarReader := tar.NewReader(r)

	_, err := os.Stat(outDir)
	if errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(outDir, 0o700)
		if err != nil {
			return fmt.Errorf("failed to create output dir and it did not exist beforehand: %w", err)
		}
	}

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar reader: %w", err)
		}

		p, err := sanitizeArchivePath(outDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			err := os.MkdirAll(p, 0o700)
			if err != nil {
				return fmt.Errorf("failed to create directory from tar: %w", err)
			}
		case tar.TypeReg:
			f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
			if err != nil {
				return fmt.Errorf("failed to file from tar: %w", err)
			}

			// G110: Potential DoS vulnerability via decompression bomb (gosec)
			_, err = io.CopyN(f, tarReader, header.Size)
			if err != nil {
				return fmt.Errorf("failed to copy tar contents to file: %w", err)
			}

			err = f.Close()
			if err != nil {
				return fmt.Errorf("failed to close file after writing: %w", err)
			}
		}
	}

	return nil
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
// all images from that IndexManifest.
func extractAllImagesFromOCIDirectory(
	outputDir string,
	ociRoot string,
	indexJSONFilename string,
) ([]trivyScannable, error) {
	var indexManifest v1.IndexManifest
	err := unmarshalJSONFromFilename(indexJSONFilename, &indexManifest)
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
		manifestLocation := path.Join(ociRoot, "blobs", digest.Algorithm, digest.Hex)
		err := unmarshalJSONFromFilename(manifestLocation, &manifest)
		if err != nil {
			return nil, err
		}

		imagesToScan = append(imagesToScan, ImageToScan{
			Name:     name,
			Manifest: &manifest,
		})
	}

	var results []trivyScannable
	for _, image := range imagesToScan {
		imageRootFS := path.Join(outputDir, replacePathChars(image.Name))

		err := os.MkdirAll(imageRootFS, 0o700)
		if err != nil {
			return nil, fmt.Errorf("failed to create dir for image %s: %w", image.Name, err)
		}

		for i := range image.Manifest.Layers {
			digest := image.Manifest.Layers[i].Digest
			layerBlob := path.Join(ociRoot, "blobs", digest.Algorithm, digest.Hex)

			f, err := os.Open(layerBlob)
			if err != nil {
				return nil, fmt.Errorf("failed to open %s: %w", layerBlob, err)
			}

			zr, err := gzip.NewReader(f)
			if err != nil {
				return nil, fmt.Errorf("failed to gunzip %s: %w", layerBlob, err)
			}
			defer zr.Close()

			err = extractTarToDir(imageRootFS, zr)
			if err != nil {
				return nil, fmt.Errorf("failed to extract tar layer %s: %w", layerBlob, err)
			}
		}

		results = append(results, rootfsScannable{
			ArtifactName: image.Name,
			RootFSDir:    imageRootFS,
		})
	}

	return results, nil
}

func ExtractRootFsFromTarFilePath(outputDir, tarFilePath string) ([]trivyScannable, error) {
	f, err := os.Open(tarFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar: %w", err)
	}

	r, err := zstd.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to unzstd tar: %w", err)
	}

	pkgOutDir := path.Join(outputDir, "oci")
	err = extractTarToDir(pkgOutDir, r)
	if err != nil {
		return nil, err
	}

	results, err := extractAllImagesFromOCIDirectory(
		outputDir,
		path.Join(pkgOutDir, "images"),
		path.Join(pkgOutDir, "images", "index.json"),
	)
	if err != nil {
		return nil, err
	}

	return results, nil
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
