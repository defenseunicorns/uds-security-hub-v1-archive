package model

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCVSSScan(t *testing.T) {
	cvssData := CVSS{
		"example": CVSSData{
			V3Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			V3Score:  9.8,
		},
	}

	data, err := json.Marshal(cvssData)
	if err != nil {
		t.Fatalf("failed to marshal CVSS data: %v", err)
	}

	var scannedCVSS CVSS
	if err := scannedCVSS.Scan(data); err != nil {
		t.Fatalf("failed to scan CVSS data: %v", err)
	}

	if diff := cmp.Diff(cvssData, scannedCVSS); diff != "" {
		t.Errorf("CVSS mismatch (-want +got):\n%s", diff)
	}
}

func TestCVSSScan_Error(t *testing.T) {
	var cvss CVSS
	err := cvss.Scan("invalid data type")
	if err == nil || err.Error() != "CVSS Scan error: expected []byte, got string" {
		t.Fatalf("expected error for invalid scan, got %v", err)
	}
}

func TestCVSSScan_UnmarshalError(t *testing.T) {
	var cvss CVSS
	err := cvss.Scan([]byte("{invalid json}"))
	if err == nil || err.Error() != "failed to unmarshal CVSS: invalid character 'i' looking for beginning of object key string" {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestCweIDsScan(t *testing.T) {
	cweIDs := CweIDs{"CWE-79", "CWE-89"}

	data, err := json.Marshal(cweIDs)
	if err != nil {
		t.Fatalf("failed to marshal CweIDs: %v", err)
	}

	var scannedCweIDs CweIDs
	if err := scannedCweIDs.Scan(data); err != nil {
		t.Fatalf("failed to scan CweIDs: %v", err)
	}

	if diff := cmp.Diff(cweIDs, scannedCweIDs); diff != "" {
		t.Errorf("CweIDs mismatch (-want +got):\n%s", diff)
	}
}

func TestCweIDsScan_Error(t *testing.T) {
	var cweIDs CweIDs
	err := cweIDs.Scan("invalid data type")
	if err == nil || err.Error() != "CweIDs Scan error: expected []byte, got string" {
		t.Fatalf("expected error for invalid scan, got %v", err)
	}
}

func TestCweIDsScan_UnmarshalError(t *testing.T) {
	var cweIDs CweIDs
	err := cweIDs.Scan([]byte("{invalid json}"))
	if err == nil || err.Error() != "failed to unmarshal CweIDs: invalid character 'i' looking for beginning of object key string" {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestDataSourceScan(t *testing.T) {
	dataSource := DataSource{
		ID:   "source-id",
		Name: "source-name",
		URL:  "http://source.url",
	}

	data, err := json.Marshal(dataSource)
	if err != nil {
		t.Fatalf("failed to marshal DataSource: %v", err)
	}

	var scannedDataSource DataSource
	if err := scannedDataSource.Scan(data); err != nil {
		t.Fatalf("failed to scan DataSource: %v", err)
	}

	if diff := cmp.Diff(dataSource, scannedDataSource); diff != "" {
		t.Errorf("DataSource mismatch (-want +got):\n%s", diff)
	}
}

func TestDataSourceScan_Error(t *testing.T) {
	var dataSource DataSource
	err := dataSource.Scan("invalid data type")
	if err == nil || err.Error() != "invalid type for DataSource" {
		t.Fatalf("expected error for invalid scan, got %v", err)
	}
}

func TestDataSourceScan_UnmarshalError(t *testing.T) {
	var dataSource DataSource
	err := dataSource.Scan([]byte("{invalid json}"))
	if err == nil || err.Error() != "failed to unmarshal DataSource: invalid character 'i' looking for beginning of object key string" {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestPkgIdentifierScan(t *testing.T) {
	pkgIdentifier := PkgIdentifier{
		PURL: "pkg:example/package@1.0.0",
		UID:  "unique-id",
	}

	data, err := json.Marshal(pkgIdentifier)
	if err != nil {
		t.Fatalf("failed to marshal PkgIdentifier: %v", err)
	}

	var scannedPkgIdentifier PkgIdentifier
	if err := scannedPkgIdentifier.Scan(data); err != nil {
		t.Fatalf("failed to scan PkgIdentifier: %v", err)
	}

	if diff := cmp.Diff(pkgIdentifier, scannedPkgIdentifier); diff != "" {
		t.Errorf("PkgIdentifier mismatch (-want +got):\n%s", diff)
	}
}

func TestPkgIdentifierScan_Error(t *testing.T) {
	var pkgIdentifier PkgIdentifier
	err := pkgIdentifier.Scan(123)
	if err == nil || err.Error() != "invalid type for PkgIdentifier" {
		t.Fatalf("expected error for invalid scan, got %v", err)
	}
}

func TestPkgIdentifierScan_UnmarshalError(t *testing.T) {
	var pkgIdentifier PkgIdentifier
	err := pkgIdentifier.Scan([]byte("{invalid json}"))
	if err == nil || err.Error() != "failed to unmarshal PkgIdentifier: invalid character 'i' looking for beginning of object key string" {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestReferencesScan(t *testing.T) {
	references := References{"http://reference1.url", "http://reference2.url"}

	data, err := json.Marshal(references)
	if err != nil {
		t.Fatalf("failed to marshal References: %v", err)
	}

	var scannedReferences References
	if err := scannedReferences.Scan(data); err != nil {
		t.Fatalf("failed to scan References: %v", err)
	}

	if diff := cmp.Diff(references, scannedReferences); diff != "" {
		t.Errorf("References mismatch (-want +got):\n%s", diff)
	}
}

func TestReferencesScan_Error(t *testing.T) {
	var references References
	err := references.Scan(123)
	if err == nil || err.Error() != "type assertion to []byte failed" {
		t.Fatalf("expected error for invalid scan, got %v", err)
	}
}

func TestReferencesScan_UnmarshalError(t *testing.T) {
	var references References
	err := references.Scan([]byte("{invalid json}"))
	if err == nil || err.Error() != "failed to unmarshal References: invalid character 'i' looking for beginning of object key string" {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestVendorSeverityScan(t *testing.T) {
	vendorSeverity := VendorSeverity{
		"vendor1": 5,
		"vendor2": 3,
	}

	data, err := json.Marshal(vendorSeverity)
	if err != nil {
		t.Fatalf("failed to marshal VendorSeverity: %v", err)
	}

	var scannedVendorSeverity VendorSeverity
	if err := scannedVendorSeverity.Scan(data); err != nil {
		t.Fatalf("failed to scan VendorSeverity: %v", err)
	}

	if diff := cmp.Diff(vendorSeverity, scannedVendorSeverity); diff != "" {
		t.Errorf("VendorSeverity mismatch (-want +got):\n%s", diff)
	}
}

func TestVendorSeverityScan_Error(t *testing.T) {
	var vendorSeverity VendorSeverity
	err := vendorSeverity.Scan("invalid data type")
	if err == nil || err.Error() != "invalid type for VendorSeverity" {
		t.Fatalf("expected error for invalid scan, got %v", err)
	}
}

func TestVendorSeverityScan_UnmarshalError(t *testing.T) {
	var vendorSeverity VendorSeverity
	err := vendorSeverity.Scan([]byte("{invalid json}"))
	if err == nil || err.Error() != "failed to unmarshal VendorSeverity: invalid character 'i' looking for beginning of object key string" {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}
