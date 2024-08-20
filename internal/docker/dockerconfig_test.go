package docker

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestParseCredentials(t *testing.T) {
	creds := []string{"example.com:user:pass"}

	// Test successful parsing
	expected := []types.RegistryCredentials{{RegistryURL: "example.com", Username: "user", Password: "pass"}}
	parsedCreds := ParseCredentials(creds)
	if diff := cmp.Diff(expected, parsedCreds); diff != "" {
		t.Errorf("ParseCredentials() mismatch (-want +got):\n%s", diff)
	}

	// Test with incorrect format
	invalidCreds := []string{"example.com:userpass"}
	parsedCreds = ParseCredentials(invalidCreds)
	if len(parsedCreds) != 0 {
		t.Errorf("Expected no credentials parsed from invalid format, got %v", parsedCreds)
	}
}
