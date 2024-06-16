package docker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zeebo/assert"
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
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
