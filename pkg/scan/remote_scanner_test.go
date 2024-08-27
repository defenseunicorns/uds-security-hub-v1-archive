package scan

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

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
			got, err := s.ScanResultReader(types.PackageScannerResult{JSONFilePath: tt.jsonFilePath})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanResultReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.GetArtifactName() != "ghcr.io/defenseunicorns/leapfrogai/rag:0.3.1" {
				t.Errorf("NewScanResultReader() got = %v, want %v", got.GetArtifactName(), "ghcr.io/defenseunicorns/leapfrogai/rag:0.3.0")
			}
			if len(got.GetVulnerabilities()) != 44 {
				t.Errorf("NewScanResultReader() got = %v, want %v", len(got.GetVulnerabilities()), 44)
			}
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
		logger          types.Logger
		ctx             context.Context
		dockerUsername  string
		dockerPassword  string
		ghrcToken       string
	}
	type args struct {
		imageRef        string
		userName        string
		password        string
		commandExecutor types.CommandExecutor
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

func Test_localScanResult_WriteToCSV(t *testing.T) {
	type fields struct {
		ScanResult types.ScanResult
	}
	tests := []struct {
		name   string
		fields fields
		want   [][]string
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
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
				{"", "CVE-2021-1234", "", "", "", "HIGH", "Test vulnerability"},
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
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
				{"", "CVE-2021-1234", "", "", "", "HIGH", "Test vulnerability 1"},
				{"", "CVE-2021-5678", "", "", "", "MEDIUM", "Test vulnerability 2"},
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
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scanResultReader{
				scanResult: tt.fields.ScanResult,
			}
			var buf bytes.Buffer
			err := s.WriteToCSV(&buf, true)
			if err != nil {
				t.Errorf("error occurred while writing to csv: %v", err)
			}
			got := buf.String()
			r := csv.NewReader(strings.NewReader(got))
			records, err := r.ReadAll()
			if err != nil {
				t.Fatalf("Failed to parse CSV: %v", err)
			}
			if diff := cmp.Diff(records, tt.want); diff != "" {
				t.Errorf("WriteToCSV() mismatch (-got +want):\n%s", diff)
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
			if got := s.GetVulnerabilities(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
