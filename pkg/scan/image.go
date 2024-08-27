package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func findImageIndexScannables(ociRootDir string) ([]trivyScannable, error) {
	indexFilename := path.Join(ociRootDir, "index.json")
	indexFile, err := os.Open(indexFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to open index.json for reading: %w", err)
	}
	defer indexFile.Close()

	var idx v1.IndexManifest
	err = json.NewDecoder(indexFile).Decode(&idx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest from index.json: %w", err)
	}

	var scannables []trivyScannable
	for _, m := range idx.Manifests {
		scannables = append(scannables, imageInputScannable{
			ArtifactName: m.Annotations["org.opencontainers.image.base.name"],
			ociDir:       ociRootDir,
			hash:         m.Digest.String(),
		})
	}

	return scannables, nil
}
