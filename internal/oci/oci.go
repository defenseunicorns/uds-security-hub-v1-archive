package oci

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/client"
)

// ImageBuildTime retrieves the build time of an OCI image.
func ImageBuildTime(imageRef string) (*time.Time, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	imageInspect, _, err := cli.ImageInspectWithRaw(context.Background(), imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	if imageInspect.Created == "" {
		return nil, fmt.Errorf("image creation time is zero")
	}

	createdTime, err := time.Parse(time.RFC3339, imageInspect.Created)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image creation time: %w", err)
	}

	return &createdTime, nil
}
