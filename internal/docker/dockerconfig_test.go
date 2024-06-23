package docker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// TestGenerateConfigText tests the GenerateConfigText function.
func TestGenerateConfigText(t *testing.T) {
	tests := []struct {
		name           string
		credentialsMap map[string]RegistryCredentials
		expected       string
		expectError    bool
	}{
		{
			name: "single registry",
			credentialsMap: map[string]RegistryCredentials{
				"ghcr.io": {
					Username: "user1",
					Password: "pass1",
				},
			},
			expected:    `{"auths":{"ghcr.io":{"auth":"dXNlcjE6cGFzczE="}}}`,
			expectError: false,
		},
		{
			name: "multiple registries",
			credentialsMap: map[string]RegistryCredentials{
				"ghcr.io": {
					Username: "user1",
					Password: "pass1",
				},
				"registry1.dso.mil": {
					Username: "user2",
					Password: "pass2",
				},
			},
			expected:    `{"auths":{"ghcr.io":{"auth":"dXNlcjE6cGFzczE="},"registry1.dso.mil":{"auth":"dXNlcjI6cGFzczI="}}}`,
			expectError: false,
		},
		{
			name:           "empty credentials",
			credentialsMap: map[string]RegistryCredentials{},
			expected:       `{"auths":{}}`,
			expectError:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GenerateConfigText(tc.credentialsMap)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected an error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("did not expect an error but got: %v", err)
				}
				if diff := cmp.Diff(tc.expected, result); diff != "" {
					t.Errorf("GenerateConfigText() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestWriteConfigToTempDir tests the WriteConfigToTempDir function.
func TestWriteConfigToTempDir(t *testing.T) {
	type args struct {
		configText string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid config text",
			args: args{
				configText: `{"auths":{"example.com":{"username":"user","password":"pass"}}}`,
			},
			wantErr: false,
		},
		{
			name: "empty config text",
			args: args{
				configText: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WriteConfigToTempDir(tt.args.configText)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteConfigToTempDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if _, err := os.Stat(got); os.IsNotExist(err) {
				t.Errorf("WriteConfigToTempDir() file does not exist: %v", got)
			}
			// Clean up
			defer os.RemoveAll(filepath.Dir(got))
		})
	}
}

func TestGenerateAndWriteDockerConfig(t *testing.T) {
	ctx := context.Background()
	credentials := []types.RegistryCredentials{
		{RegistryURL: "https://example.com", Username: "user", Password: "pass"},
	}

	// Test successful execution
	dir, err := GenerateAndWriteDockerConfig(ctx, credentials)
	if err != nil {
		t.Errorf("GenerateAndWriteDockerConfig() error = %v", err)
	}
	if dir == "" {
		t.Errorf("Expected non-empty directory path, got empty string")
	}

	// Test with empty credentials
	emptyCreds := []types.RegistryCredentials{}
	dir, err = GenerateAndWriteDockerConfig(ctx, emptyCreds)
	if err != nil {
		t.Errorf("GenerateAndWriteDockerConfig() with empty credentials error = %v", err)
	}
	if dir == "" {
		t.Errorf("Expected non-empty directory path with empty credentials, got empty string")
	}
}

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
