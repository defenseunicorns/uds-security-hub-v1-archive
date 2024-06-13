package db

import (
	"context"

	"github.com/defenseunicorns/uds-security-hub/internal/external"
)

type PackageManager interface {
	InsertPackage(ctx context.Context, dto *external.PackageDTO) error
}
