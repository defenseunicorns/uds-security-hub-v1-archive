package db

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

func TestReport(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	err = db.AutoMigrate(&model.Report{})
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	report := &model.Report{
		PackageName: "example-package",
		Tag:         "0.0.1",
		Critical:    1,
		High:        2,
		Medium:      3,
		Low:         4,
		Info:        5,
		Total:       6,
		SBOM:        []byte(`{"dependencies": [{"name": "example-dependency", "version": "1.0.0"}]}`),
	}
	err = InsertReport(db, report)
	if err != nil {
		t.Fatalf("failed to insert report: %v", err)
	}
	report, err = GetReport(db, report.ID)
	if err != nil {
		t.Fatalf("failed to get report: %v", err)
	}
	if diff := cmp.Diff(report, report); diff != "" {
		t.Fatalf("report mismatch (-want +got):\n%s", diff)
	}
}
