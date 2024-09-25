package scan

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// ScannerFactoryImpl is the implementation of the ScannerFactory interface.
type ScannerFactoryImpl struct{}

// CreateScanner creates a new PackageScanner based on the provided options.
func (sf *ScannerFactoryImpl) CreateScanner(
	ctx context.Context,
	logger *slog.Logger,
	org, packageName, tag, packagePath, offlineDBPath string,
	registryCredentials []types.RegistryCredentials,
	scannerType ScannerType,
) (types.PackageScanner, error) {
	if packagePath != "" {
		return NewLocalPackageScanner(logger, packagePath, offlineDBPath, scannerType)
	}

	if org == "" || packageName == "" || tag == "" {
		return nil, fmt.Errorf("org, packageName, and tag are required for remote scanning")
	}

	return NewRemotePackageScanner(
		ctx,
		logger,
		org,
		packageName,
		tag,
		offlineDBPath,
		registryCredentials,
		scannerType,
	), nil
}
