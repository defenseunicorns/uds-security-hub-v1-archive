package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
)

// TestNewStoreCmd tests the newStoreCmd function.
func TestNewStoreCmd(t *testing.T) {
	cmd := newStoreCmd()

	if cmd.Use != "store" {
		t.Errorf("command use mismatch: got %v, want %v", cmd.Use, "store")
	}
	if cmd.Short != "Scan a Zarf package and store the results in the database" {
		t.Errorf("command short description mismatch: got %v, want %v", cmd.Short, "Scan a Zarf package and store the results in the database")
	}
	if cmd.Long != "Scan a Zarf package for vulnerabilities and store the results in the database using GormScanManager" {
		t.Errorf("command long description mismatch: got %v, want %v", cmd.Long, "Scan a Zarf package for vulnerabilities and store the results in the database using GormScanManager")
	}

	flags := []struct {
		name         string
		shorthand    string
		defaultValue string
		usage        string
	}{
		{"docker-username", "u", "", "Optional: Docker username for registry access, accepts CSV values"},
		{"docker-password", "p", "", "Optional: Docker password for registry access, accepts CSV values"},
		{"org", "o", "defenseunicorns", "Organization name"},
		{"package-name", "n", "", "Package Name: packages/uds/gitlab-runner"},
		{"tag", "g", "", "Tag name (e.g.  16.10.0-uds.0-upstream)"},
		{"db-host", "", "localhost", "Database host"},
		{"db-user", "", "test_user", "Database user"},
		{"db-password", "", "test_password", "Database password"},
		{"db-name", "", "test_db", "Database name"},
		{"db-port", "", "5432", "Database port"},
		{"db-ssl-mode", "", "disable", "Database SSL mode"},
	}

	for _, flag := range flags {
		f := cmd.PersistentFlags().Lookup(flag.name)
		if f == nil {
			t.Errorf("flag %s should be defined", flag.name)
		} else {
			if f.DefValue != flag.defaultValue {
				t.Errorf("default value for flag %s mismatch: got %v, want %v", flag.name, f.DefValue, flag.defaultValue)
			}
			if f.Usage != flag.usage {
				t.Errorf("usage for flag %s mismatch: got %v, want %v", flag.name, f.Usage, flag.usage)
			}
		}
	}
}

// TestSetupDBConnection_Failure tests the setupDBConnection function with an invalid connection string.
func TestSetupDBConnection_Failure(t *testing.T) {
	// Use an invalid connection string
	connStr := "host=invalid port=5432 user=invalid dbname=invalid password=invalid sslmode=disable"

	_, err := setupDBConnection(connStr)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

// Test_getConfigFromFlags tests the getConfigFromFlags function.
func Test_getConfigFromFlags(t *testing.T) {
	type args struct {
		cmd *cobra.Command
	}
	tests := []struct {
		name    string
		want    *Config
		wantErr bool
		args    args
	}{
		{
			name: "Valid flags",
			args: args{
				cmd: func() *cobra.Command {
					cmd := &cobra.Command{}
					cmd.PersistentFlags().String("docker-username", "testuser", "Docker username")
					cmd.PersistentFlags().String("docker-password", "testpass", "Docker password")
					cmd.PersistentFlags().String("org", "testorg", "Organization name")
					cmd.PersistentFlags().String("package-name", "testpackage", "Package name")
					cmd.PersistentFlags().String("tag", "testtag", "Tag name")
					cmd.PersistentFlags().String("db-host", "localhost", "Database host")
					cmd.PersistentFlags().String("db-user", "test_user", "Database user")
					cmd.PersistentFlags().String("db-password", "test_password", "Database password")
					cmd.PersistentFlags().String("db-name", "test_db", "Database name")
					cmd.PersistentFlags().String("db-port", "5432", "Database port")
					cmd.PersistentFlags().String("db-ssl-mode", "disable", "Database SSL mode")
					cmd.ParseFlags([]string{}) //nolint:errcheck
					return cmd
				}(),
			},
			want: &Config{
				ConnStr:        "host=localhost port=5432 user=test_user dbname=test_db password=test_password sslmode=disable",
				DockerUsername: "testuser",
				DockerPassword: "testpass",
				Org:            "testorg",
				PackageName:    "testpackage",
				Tag:            "testtag",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getConfigFromFlags(tt.args.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("getConfigFromFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("getConfigFromFlags() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_storeScanResults tests the storeScanResults function.
func Test_storeScanResults(t *testing.T) {
	ctx := context.Background()
	mockScanner := new(MockScanner)
	mockManager := new(MockScanManager)
	config := &Config{
		Org:         "test-org",
		PackageName: "test-package",
		Tag:         "test-tag",
	}

	// Mock scan results
	scanResults := []string{"result1.json", "result2.json"}
	mockScanner.On("ScanZarfPackage", config.Org, config.PackageName, config.Tag).Return(scanResults, nil)

	// Mock reading files and unmarshalling JSON
	for _, result := range scanResults {
		data := `{"some": "data"}`
		os.WriteFile(result, []byte(data), 0o600) //nolint:errcheck
		defer os.Remove(result)
	}

	// Mock the InsertPackageScans method
	mockManager.On("InsertPackageScans", ctx, mock.AnythingOfType("*external.PackageDTO")).Return(nil)

	// Call the function with the mocks
	err := storeScanResults(ctx, mockScanner, mockManager, config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// Mock for the Scanner interface.
type MockScanner struct {
	mock.Mock
}

// ScanZarfPackage is a mock implementation of the ScanZarfPackage method.
func (m *MockScanner) ScanZarfPackage(org, packageName, tag string) ([]string, error) {
	args := m.Called(org, packageName, tag)
	return args.Get(0).([]string), args.Error(1)
}

// Mock for the ScanManager interface.
type MockScanManager struct {
	mock.Mock
}

// InsertPackageScans is a mock implementation of the InsertPackageScans method.
func (m *MockScanManager) InsertPackageScans(ctx context.Context, packageDTO *external.PackageDTO) error {
	args := m.Called(ctx, packageDTO)
	return args.Error(0)
}

// Test_runStoreScannerWithDeps tests the runStoreScannerWithDeps function.
func Test_runStoreScannerWithDeps(t *testing.T) {
	tests := []struct {
		name    string
		scanner Scanner
		manager ScanManager
		cmd     *cobra.Command
		wantErr bool
	}{
		{
			name:    "Nil scanner",
			scanner: nil,
			manager: new(MockScanManager),
			cmd:     &cobra.Command{},
			wantErr: true,
		},
		{
			name:    "Nil manager",
			scanner: new(MockScanner),
			manager: nil,
			cmd:     &cobra.Command{},
			wantErr: true,
		},
		{
			name:    "Nil command",
			scanner: new(MockScanner),
			manager: new(MockScanManager),
			cmd:     nil,
			wantErr: true,
		},
		{
			name: "Valid inputs",
			scanner: func() *MockScanner {
				mockScanner := new(MockScanner)
				mockScanner.On("ScanZarfPackage", "testorg", "testpackage", "testtag").Return([]string{"result1.json", "result2.json"}, nil)
				return mockScanner
			}(),
			manager: func() *MockScanManager {
				mockManager := new(MockScanManager)
				mockManager.On("InsertPackageScans", mock.Anything, mock.AnythingOfType("*external.PackageDTO")).Return(nil)
				return mockManager
			}(),
			cmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.PersistentFlags().String("docker-username", "testuser", "Docker username")
				cmd.PersistentFlags().String("docker-password", "testpass", "Docker password")
				cmd.PersistentFlags().String("org", "testorg", "Organization name")
				cmd.PersistentFlags().String("package-name", "testpackage", "Package name")
				cmd.PersistentFlags().String("tag", "testtag", "Tag name")
				cmd.PersistentFlags().String("db-host", "localhost", "Database host")
				cmd.PersistentFlags().String("db-user", "test_user", "Database user")
				cmd.PersistentFlags().String("db-password", "test_password", "Database password")
				cmd.PersistentFlags().String("db-name", "test_db", "Database name")
				cmd.PersistentFlags().String("db-port", "5432", "Database port")
				cmd.PersistentFlags().String("db-ssl-mode", "disable", "Database SSL mode")
				cmd.ParseFlags([]string{}) //nolint:errcheck
				return cmd
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Valid inputs" {
				// Create mock scan result files
				os.WriteFile("result1.json", []byte(`{"some": "data"}`), 0o600) //nolint:errcheck
				os.WriteFile("result2.json", []byte(`{"some": "data"}`), 0o600) //nolint:errcheck
				defer os.Remove("result1.json")
				defer os.Remove("result2.json")
			}

			err := runStoreScannerWithDeps(context.Background(), tt.cmd, log.NewLogger(context.Background()), tt.scanner, tt.manager)
			if (err != nil) != tt.wantErr {
				t.Errorf("runStoreScannerWithDeps() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGenerateAndWriteDockerConfig tests the generateAndWriteDockerConfig function.
func TestGenerateAndWriteDockerConfig(t *testing.T) {
	tests := []struct {
		name                string
		envVars             map[string]string
		expectedFileContent string
		expectError         bool
	}{
		{
			name: "valid credentials",
			envVars: map[string]string{
				"GHCR_USERNAME":      "user1",
				"GHCR_PASSWORD":      "pass1",
				"REGISTRY1_USERNAME": "user2",
				"REGISTRY1_PASSWORD": "pass2",
			},
			expectedFileContent: `{
				"auths": {
					"ghcr.io": {
						"auth": "dXNlcjE6cGFzczE="
					},
					"registry1.dso.mil": {
						"auth": "dXNlcjI6cGFzczI="
					}
				}
			}`,
			expectError: false,
		},
		{
			name: "missing credentials",
			envVars: map[string]string{
				"GHCR_USERNAME": "",
				"GHCR_PASSWORD": "",
			},
			expectedFileContent: `{"auths": {}}`,
			expectError:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variables as per test case
			for key, value := range tc.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			dir, err := generateAndWriteDockerConfig(context.Background())
			if tc.expectError { //nolint:nestif
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				// Read the file content from the directory
				files, err := os.ReadDir(dir)
				if err != nil {
					t.Errorf("Error reading directory: %v", err)
				}
				if len(files) == 0 {
					t.Errorf("Expected at least one file in the directory")
				}

				content, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
				if err != nil {
					t.Errorf("Error reading file: %v", err)
				}

				var got, want map[string]interface{}
				if err := json.Unmarshal(content, &got); err != nil {
					t.Errorf("Error unmarshalling JSON: %v", err)
				}
				if err := json.Unmarshal([]byte(tc.expectedFileContent), &want); err != nil {
					t.Errorf("Error unmarshalling expected JSON: %v", err)
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
