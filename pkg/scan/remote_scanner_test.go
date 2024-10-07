package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestNewScanResultReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		want         types.ScanResultReader
		jsonFilePath string
		wantErr      bool
	}{
		{
			name:         "Test with valid scan result",
			jsonFilePath: "testdata/scanresult.json",
			wantErr:      false,
		},
	}
	s := NewRemotePackageScanner(context.Background(), nil, "test", "test", "test", "test", nil, RootFSScannerType)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			got, err := s.ScanResultReader(types.PackageScannerResult{JSONFilePath: tt.jsonFilePath})
			if tt.wantErr {
				require.Error(err, "expected an error but got none")
			} else {
				require.NoError(err, "expected no error but got one")
			}
			require.Equal("ghcr.io/defenseunicorns/leapfrogai/rag:0.3.1", got.GetArtifactName(), "artifact name mismatch")
			require.Equal(44, len(got.GetVulnerabilities()), "Vulnerabilities count mismatch")
		})
	}
}

// MockCommandExecutor is a mock implementation of the CommandExecutor interface.
type MockCommandExecutor struct {
	err    error
	output string
}

func (m *MockCommandExecutor) Execute(command string, args ...string) (string, error) {
	return m.output, m.err
}

// Update the ExecuteCommand method to match the expected signature.
func (m *MockCommandExecutor) ExecuteCommand(command string, args, env []string) (string, string, error) {
	return m.output, "", m.err
}

func TestScanner_scanWithTrivy(t *testing.T) {
	t.Parallel()
	type fields struct {
		commandExecutor types.CommandExecutor
		logger          *slog.Logger
		ctx             context.Context
		dockerUsername  string
		dockerPassword  string
		ghrcToken       string
	}
	type args struct {
		commandExecutor types.CommandExecutor
		imageRef        string
		userName        string
		password        string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Success",
			fields: fields{
				ctx:             context.Background(),
				commandExecutor: &MockCommandExecutor{output: "scan result", err: nil},
				logger:          nil,
				dockerUsername:  "dockerUsername",
				dockerPassword:  "dockerPassword",
				ghrcToken:       "ghcrToken",
			},
			args: args{
				imageRef:        "test/image:latest",
				userName:        "trivyUsername",
				password:        "trivyPassword",
				commandExecutor: &MockCommandExecutor{output: "scan result", err: nil},
			},
			want:    "scan result",
			wantErr: false,
		},
		{
			name: "Failure",
			fields: fields{
				ctx:             context.Background(),
				commandExecutor: &MockCommandExecutor{output: "", err: io.ErrUnexpectedEOF},
				logger:          nil,
				dockerUsername:  "dockerUsername",
				dockerPassword:  "dockerPassword",
				ghrcToken:       "ghcrToken",
			},
			args: args{
				imageRef:        "test/image:latest",
				userName:        "trivyUsername",
				password:        "trivyPassword",
				commandExecutor: &MockCommandExecutor{output: "", err: io.ErrUnexpectedEOF},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scanWithTrivy(&rootfsScannable{RootFSDir: "/dev/null"}, "", tt.args.commandExecutor)
			if (err != nil) != tt.wantErr {
				t.Errorf("scanWithTrivy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.JSONFilePath == "" {
				t.Errorf("scanWithTrivy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_localScanResult_GetVulnerabilities(t *testing.T) {
	type fields struct {
		ScanResult types.ScanResult
	}
	tests := []struct {
		name   string
		fields fields
		want   []types.VulnerabilityInfo
	}{
		{
			name: "Single Vulnerability",
			fields: fields{
				ScanResult: types.ScanResult{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability",
									Severity:        "HIGH",
								},
							},
						},
					},
				},
			},
			want: []types.VulnerabilityInfo{
				{
					VulnerabilityID: "CVE-2021-1234",
					Description:     "Test vulnerability",
					Severity:        "HIGH",
				},
			},
		},
		{
			name: "Multiple Vulnerabilities",
			fields: fields{
				ScanResult: types.ScanResult{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-1234",
									Description:     "Test vulnerability 1",
									Severity:        "HIGH",
								},
								{
									VulnerabilityID: "CVE-2021-5678",
									Description:     "Test vulnerability 2",
									Severity:        "MEDIUM",
								},
							},
						},
					},
				},
			},
			want: []types.VulnerabilityInfo{
				{
					VulnerabilityID: "CVE-2021-1234",
					Description:     "Test vulnerability 1",
					Severity:        "HIGH",
				},
				{
					VulnerabilityID: "CVE-2021-5678",
					Description:     "Test vulnerability 2",
					Severity:        "MEDIUM",
				},
			},
		},
		{
			name: "No Vulnerabilities",
			fields: fields{
				ScanResult: types.ScanResult{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{},
						},
					},
				},
			},
			want: []types.VulnerabilityInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scanResultReader{
				scanResult: tt.fields.ScanResult,
			}
			got := s.GetVulnerabilities()
			require.Equal(t, tt.want, got, "GetVulnerabilities() mismatch")
		})
	}
}

type MockScanner struct {
	Scanner
	mock.Mock
}

func (m *MockScanner) Scan(ctx context.Context) (*types.PackageScan, error) {
	args := m.Called(ctx)
	return args.Get(0).(*types.PackageScan), args.Error(1)
}

func TestScanner_ScanZarfPackage(t *testing.T) {
	tests := []struct {
		name        string
		org         string
		packageName string
		tag         string
		mockScan    func(*MockScanner)
		wantErr     bool
	}{
		{
			name:        "Missing org",
			org:         "",
			packageName: "valid-package",
			tag:         "valid-tag",
			wantErr:     true,
		},
		{
			name:        "Missing packageName",
			org:         "valid-org",
			packageName: "",
			tag:         "valid-tag",
			wantErr:     true,
		},
		{
			name:        "Missing tag",
			org:         "valid-org",
			packageName: "valid-package",
			tag:         "",
			wantErr:     true,
		},
		{
			name:        "Scan failure",
			org:         "valid-org",
			packageName: "valid-package",
			tag:         "valid-tag",
			mockScan: func(m *MockScanner) {
				m.On("Scan", mock.Anything).Return((*types.PackageScan)(nil), errors.New("mock scan error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockScanner := &MockScanner{}

			if tt.mockScan != nil {
				tt.mockScan(mockScanner)
			}

			_, err := mockScanner.ScanZarfPackage(tt.org, tt.packageName, tt.tag)

			if tt.wantErr {
				require.Error(t, err, "expected an error but got none")
			} else {
				require.NoError(t, err, "did not expect an error but got one")
			}

			if !tt.wantErr {
				mockScanner.AssertCalled(t, "Scan", mock.Anything)
			} else {
				mockScanner.AssertNotCalled(t, "Scan", mock.Anything)
			}
		})
	}
}
