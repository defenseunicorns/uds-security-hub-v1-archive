package scan

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

func TestWriteToJSON(t *testing.T) {
	scanResult := types.ScanResult{
		ArtifactName: "test-artifact",
		Results: []struct {
			Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
		}{
			{
				Vulnerabilities: []types.VulnerabilityInfo{
					{
						VulnerabilityID:  "CVE-2021-1234",
						PkgName:          "test-package",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						Severity:         "HIGH",
						Description:      "Test vulnerability",
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteToJSON(&buf, []types.ScanResultReader{scanResult}) // Call method on reader
	require.NoError(t, err)

	var output []JSONOutputEntry
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, len(output), 1, "there should only be 1 result in this output")

	firstResult := output[0]

	require.Equal(t, "test-artifact", firstResult.ArtifactName)
	assert.Equal(t, "CVE-2021-1234", firstResult.VulnerabilityID)
	assert.Equal(t, "test-package", firstResult.PkgName)
	assert.Equal(t, "1.0.0", firstResult.InstalledVersion)
	assert.Equal(t, "1.0.1", firstResult.FixedVersion)
	assert.Equal(t, "HIGH", firstResult.Severity)
	assert.Equal(t, "Test vulnerability", firstResult.Description)
}

func TestWriteToCSV(t *testing.T) {
	tests := []struct {
		name        string
		ScanResults []types.ScanResult
		want        [][]string
	}{
		{
			name: "Single Vulnerability",
			ScanResults: []types.ScanResult{
				{
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
			ScanResults: []types.ScanResult{
				{
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
				{
					Results: []struct {
						Vulnerabilities []types.VulnerabilityInfo `json:"Vulnerabilities"`
					}{
						{
							Vulnerabilities: []types.VulnerabilityInfo{
								{
									VulnerabilityID: "CVE-2021-4321",
									Description:     "Test vulnerability 3",
									Severity:        "HIGH",
								},
								{
									VulnerabilityID: "CVE-2021-8765",
									Description:     "Test vulnerability 4",
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
				{"", "CVE-2021-4321", "", "", "", "HIGH", "Test vulnerability 3"},
				{"", "CVE-2021-8765", "", "", "", "MEDIUM", "Test vulnerability 4"},
			},
		},
		{
			name: "No Vulnerabilities",
			ScanResults: []types.ScanResult{
				{
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
		{
			name: "Artifact Name",
			ScanResults: []types.ScanResult{
				{
					ArtifactName: "override-artifact-name:v0.1.1",
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
							},
						},
					},
				},
			},
			want: [][]string{
				{"ArtifactName", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Description"},
				{"override-artifact-name:v0.1.1", "CVE-2021-1234", "", "", "", "HIGH", "Test vulnerability 1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var allResults []types.ScanResultReader
			for _, r := range tt.ScanResults {
				allResults = append(allResults, &scanResultReader{"", r})
			}

			var buf bytes.Buffer
			err := WriteToCSV(&buf, allResults)
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
