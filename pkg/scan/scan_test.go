package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	version "github.com/google/go-containerregistry/pkg/v1/types"

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
	s, err := New(context.Background(), nil, "trivyUsername", "trivyPassword", "ghcrToken")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ScanResultReader(tt.jsonFilePath)
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

// mockLayer implements the v1.Layer interface for testing purposes.
type mockLayer struct {
	content []byte
}

func (m *mockLayer) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (m *mockLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (m *mockLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.content)), nil
}

func (m *mockLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.content)), nil
}

func (m *mockLayer) Size() (int64, error) {
	return int64(len(m.content)), nil
}

func (m *mockLayer) MediaType() (version.MediaType, error) {
	return version.DockerLayer, nil
}

// createMockLayer creates a mock layer with the specified content for testing.
func createMockLayer(content []byte) v1.Layer {
	return &mockLayer{content: content}
}

// Helper function to create a mock tar file containing JSON data.
func createMockTarReaderWithJSON(t *testing.T, jsonContent string) io.Reader {
	t.Helper()
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	// Create a header
	hdr := &tar.Header{
		Name: "data.json",
		Mode: 0o600,
		Size: int64(len(jsonContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(jsonContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return bytes.NewReader(buf.Bytes())
}
func Test_extractSBOMPackages(t *testing.T) {
	type args struct {
		ctx   context.Context
		layer v1.Layer
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "Success - Single Tag",
			args: args{
				ctx: context.Background(),
				layer: createMockLayer(func() []byte {
					// Using the structure from Test_readTagsFromLayerFile for SBOM data
					sbomData := `{"Source": {"Metadata": {"Tags": ["v1.0.0"]}}}`
					reader := createMockTarReaderWithJSON(t, sbomData)
					var buf bytes.Buffer
					io.Copy(&buf, reader) //nolint:errcheck    // Assuming this operation succeeds without error for simplicity
					return buf.Bytes()
				}()),
			},
			want:    []string{"v1.0.0"},
			wantErr: false,
		},
		{
			name: "Success - Multiple Tags",
			args: args{
				ctx: context.Background(),
				layer: createMockLayer(func() []byte {
					// Using the structure from Test_readTagsFromLayerFile for SBOM data with multiple tags
					sbomData := `{"Source": {"Metadata": {"Tags": ["v1.0.0", "v1.0.1"]}}}`
					reader := createMockTarReaderWithJSON(t, sbomData)
					var buf bytes.Buffer
					io.Copy(&buf, reader) //nolint:errcheck    // Assuming this operation succeeds without error for simplicity
					return buf.Bytes()
				}()),
			},
			want:    []string{"v1.0.0", "v1.0.1"},
			wantErr: false,
		},
		{
			name: "Failure - Invalid JSON",
			args: args{
				ctx: context.Background(),
				layer: createMockLayer(func() []byte {
					// Using the structure from Test_readTagsFromLayerFile but with invalid JSON
					sbomData := `{"Source": {"Metadata": {"Tags": ["v1.0.0",]}}}` // Invalid JSON due to trailing comma
					reader := createMockTarReaderWithJSON(t, sbomData)
					var buf bytes.Buffer
					io.Copy(&buf, reader) //nolint:errcheck    // Assuming this operation succeeds without error for simplicity
					return buf.Bytes()
				}()),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Failure - No Tags Field",
			args: args{
				ctx: context.Background(),
				layer: createMockLayer(func() []byte {
					// Using the structure from Test_readTagsFromLayerFile but missing the "Tags" field
					sbomData := `{"Source": {"Metadata": {}}}` // Missing "Tags" field
					reader := createMockTarReaderWithJSON(t, sbomData)
					var buf bytes.Buffer
					io.Copy(&buf, reader) //nolint:errcheck    // Assuming this operation succeeds without error for simplicity
					return buf.Bytes()
				}()),
			},
			want:    nil,
			wantErr: false,
		},
	}
	s, err := New(context.Background(), nil, "trivyUsername", "trivyPassword", "ghcrToken")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.extractSBOMPackages(tt.args.ctx, tt.args.layer)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractSBOMPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractSBOMPackages() got = %v, want %v", got, tt.want)
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
		trivyUsername   string
		trivyPassword   string
		ghrcToken       string
	}
	type args struct { //nolint:govet
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
				trivyUsername:   "trivyUsername",
				trivyPassword:   "trivyPassword",
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
				trivyUsername:   "trivyUsername",
				trivyPassword:   "trivyPassword",
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
			s := &Scanner{
				ctx:             tt.fields.ctx,
				commandExecutor: tt.fields.commandExecutor,
				logger:          tt.fields.logger,
				trivyUsername:   tt.fields.trivyUsername,
				trivyPassword:   tt.fields.trivyPassword,
				ghrcToken:       tt.fields.ghrcToken,
			}
			got, err := s.scanWithTrivy(tt.args.imageRef, tt.args.userName, tt.args.password, tt.args.commandExecutor)
			if (err != nil) != tt.wantErr {
				t.Errorf("scanWithTrivy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == "" {
				t.Errorf("scanWithTrivy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_localScanResult_GetResultsAsCSV(t *testing.T) {
	type fields struct {
		ScanResult types.ScanResult
	}
	tests := []struct {
		name   string
		fields fields
		want   string
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
			want: "ArtifactName,VulnerabilityID,PkgName,InstalledVersion,FixedVersion,Severity,Description\n,CVE-2021-1234,,,,HIGH,Test vulnerability\n",
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
			want: "ArtifactName,VulnerabilityID,PkgName,InstalledVersion,FixedVersion,Severity,Description\n,CVE-2021-1234,,,,HIGH,Test vulnerability 1\n,CVE-2021-5678,,,,MEDIUM,Test vulnerability 2\n",
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
			want: "ArtifactName,VulnerabilityID,PkgName,InstalledVersion,FixedVersion,Severity,Description\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &localScanResult{
				ScanResult: tt.fields.ScanResult,
			}
			if got := s.GetResultsAsCSV(); got != tt.want {
				t.Errorf("GetResultsAsCSV() = %v, want %v", got, tt.want)
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
			s := &localScanResult{
				ScanResult: tt.fields.ScanResult,
			}
			if got := s.GetVulnerabilities(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
