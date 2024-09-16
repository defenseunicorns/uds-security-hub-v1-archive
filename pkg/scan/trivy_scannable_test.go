package scan

import (
	"testing"
)

func TestScannerType_String(t *testing.T) {
	tests := []struct {
		name     string
		scanner  ScannerType
		expected string
	}{
		{"SBOM Scanner", SBOMScannerType, "sbom"},
		{"RootFS Scanner", RootFSScannerType, "rootfs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scanner.String(); got != tt.expected {
				t.Errorf("ScannerType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScannerType_Set(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{"Valid SBOM Scanner", "sbom", false},
		{"Valid RootFS Scanner", "rootfs", false},
		{"Invalid Scanner", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scanner ScannerType
			err := scanner.Set(tt.input)
			if (err != nil) != tt.expectErr {
				t.Errorf("ScannerType.Set() error = %v, wantErr %v", err, tt.expectErr)
			}
			if !tt.expectErr && scanner.String() != tt.input {
				t.Errorf("Expected scanner to be set to %v, but got %v", tt.input, scanner.String())
			}
		})
	}
}

func TestScannerType_Type(t *testing.T) {
	scanner := ScannerType("any")
	expectedType := "ScannerType"

	if got := scanner.Type(); got != expectedType {
		t.Errorf("ScannerType.Type() = %v, want %v", got, expectedType)
	}
}
