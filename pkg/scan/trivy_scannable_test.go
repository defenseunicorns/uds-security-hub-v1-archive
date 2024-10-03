package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
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
			got := tt.scanner.String()
			require.Equal(t, tt.expected, got, "ScannerType.Type() mismatch (-got +want):\n%s")
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
			if tt.expectErr {
				require.Error(t, err, "expected an error but got none")
			} else {
				require.NoError(t, err, "expected no error but got one")
				require.Equal(t, tt.input, scanner.String(), "expected scanner to be set to %v, but got %v", tt.input, scanner.String())
			}
		})
	}
}

func TestScannerType_Type(t *testing.T) {
	scanner := ScannerType("any")
	expectedType := "ScannerType"

	got := scanner.Type()
	require.Equal(t, expectedType, got, "ScannerType.Type() mismatch (-got +want):\n%s")
}
