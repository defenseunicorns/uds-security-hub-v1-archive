package db

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
)

// ScanManager defines the interface for managing scans in the database.
type ScanManager interface {
	// InsertScan inserts a new Scan and its associated Vulnerabilities into the database.
	InsertScan(ctx context.Context, dto external.ScanDTO) error
	// UpdateScan updates an existing Scan and its associated Vulnerabilities in the database.
	UpdateScan(ctx context.Context, dto external.ScanDTO) error
	// GetScan retrieves a Scan and its associated Vulnerabilities from the database.
	GetScan(ctx context.Context, id uint) (*model.Scan, error)
}

// GormScanManager implements the ScanManager interface using a GORM DB connection.
type GormScanManager struct {
	db *gorm.DB
}

// NewGormScanManager creates a new GormScanManager.
func NewGormScanManager(db *gorm.DB) (*GormScanManager, error) {
	if db == nil {
		return nil, fmt.Errorf("db cannot be nil")
	}
	return &GormScanManager{db: db}, nil
}

// InsertScan inserts a new Scan and its associated Vulnerabilities into the database.
func (manager *GormScanManager) InsertScan(ctx context.Context, dto *external.ScanDTO) error {
	if manager.db == nil {
		return fmt.Errorf("db cannot be nil")
	}
	if ctx == nil {
		return fmt.Errorf("ctx cannot be nil")
	}
	logger := log.NewLogger(ctx)
	logger.Debug("InsertScan", zap.Any("dto", dto))
	scan := model.Scan{
		SchemaVersion:   dto.SchemaVersion,
		CreatedAt:       dto.CreatedAt,
		ArtifactName:    dto.ArtifactName,
		ArtifactType:    dto.ArtifactType,
		Metadata:        dto.Metadata,
		Vulnerabilities: dto.Vulnerabilities,
	}

	if err := manager.db.Create(&scan).Error; err != nil {
		return fmt.Errorf("error creating scan: %w", err)
	}
	return nil
}

// UpdateScan updates an existing Scan and its associated Vulnerabilities in the database.
func (manager *GormScanManager) UpdateScan(ctx context.Context, _ *external.ScanDTO) error {
	if ctx == nil {
		return fmt.Errorf("ctx cannot be nil")
	}
	if manager.db == nil {
		return fmt.Errorf("db cannot be nil")
	}
	return nil
}

// GetScan retrieves a Scan and its associated Vulnerabilities from the database.
func (manager *GormScanManager) GetScan(ctx context.Context, _ *gorm.DB, _ uint) (*model.Scan, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ctx cannot be nil")
	}
	if manager.db == nil {
		return nil, fmt.Errorf("db cannot be nil")
	}
	return nil, nil
}
