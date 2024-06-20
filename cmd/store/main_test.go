package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"
	"github.com/zeebo/assert"

	"github.com/defenseunicorns/uds-security-hub/internal/external"
	"github.com/defenseunicorns/uds-security-hub/internal/github"
	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/pkg/types"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c *Config
			var err error
			if tt.name == "Valid inputs" {
				// Create mock scan result files
				os.WriteFile("result1.json", []byte(`{"some": "data"}`), 0o600) //nolint:errcheck
				os.WriteFile("result2.json", []byte(`{"some": "data"}`), 0o600) //nolint:errcheck
				defer os.Remove("result1.json")
				defer os.Remove("result2.json")

				c, err = getConfigFromFlags(tt.cmd)
				c.Tag = "testtag"
				if err != nil {
					t.Fatalf("getConfigFromFlags() error = %v", err)
				}
			}

			err = runStoreScannerWithDeps(context.Background(), tt.cmd, log.NewLogger(context.Background()), tt.scanner, tt.manager, c)
			if (err != nil) != tt.wantErr {
				t.Errorf("runStoreScannerWithDeps() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateAndWriteDockerConfig(t *testing.T) {
	tests := []struct {
		name                string
		credentials         []types.RegistryCredentials
		expectedFileContent string
		expectError         bool
	}{
		{
			name: "valid credentials",
			credentials: []types.RegistryCredentials{
				{RegistryURL: "ghcr.io", Username: "user1", Password: "pass1"},
				{RegistryURL: "registry1.dso.mil", Username: "user2", Password: "pass2"},
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
			credentials: []types.RegistryCredentials{
				{RegistryURL: "ghcr.io", Username: "", Password: ""},
				{RegistryURL: "registry1.dso.mil", Username: "", Password: ""},
			},
			expectedFileContent: `{"auths": {}}`,
			expectError:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := generateAndWriteDockerConfig(context.Background(), tc.credentials)
			if (err != nil) != tc.expectError {
				t.Errorf("generateAndWriteDockerConfig() error = %v, expectError %v", err, tc.expectError)
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
		})
	}
}

func TestGetPackageVersions(t *testing.T) {
	tests := []struct {
		name          string
		org           string
		packageName   string
		gitHubToken   string
		mockFunc      func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error)
		expectedError bool
		expectedTag   string
		expectedDate  time.Time
	}{
		{
			name:        "successful retrieval",
			org:         "defenseunicorns",
			packageName: "test-package",
			gitHubToken: "test-token",
			mockFunc: func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error) {
				return []github.VersionTagDate{
					{Tags: []string{"v1.0.0"}, Date: time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC)},
				}, nil
			},
			expectedError: false,
			expectedTag:   "v1.0.0",
			expectedDate:  time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:        "error from GitHub API",
			org:         "defenseunicorns",
			packageName: "test-package",
			gitHubToken: "test-token",
			mockFunc: func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error) {
				return nil, fmt.Errorf("API error")
			},
			expectedError: true,
		},
		{
			name:        "empty parameters",
			org:         "",
			packageName: "",
			gitHubToken: "",
			mockFunc: func(ctx context.Context, client types.HTTPClientInterface, token, org, packageType, packageName string) ([]github.VersionTagDate, error) {
				return nil, fmt.Errorf("invalid parameters")
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Override the getVersionTagDate function with the mock function
			getVersionTagDate = tt.mockFunc

			// Call the function under test
			version, err := getVersionTagDate(context.Background(), nil, tt.gitHubToken, tt.org, "defenseunicorns", tt.packageName)

			// Check for expected error
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, version)
				assert.Equal(t, tt.expectedTag, version[0].Tags[0])
				assert.Equal(t, tt.expectedDate, version[0].Date)
			}
		})
	}
}
