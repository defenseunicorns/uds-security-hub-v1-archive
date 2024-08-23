package scan

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

type scanResultReaderImpl struct {
	scanResult types.ScanResult
}

func (r *scanResultReaderImpl) WriteToJSON(buf io.Writer, results []types.ScanResultReader) error {
	return json.NewEncoder(buf).Encode(r.scanResult)
}

func (r *scanResultReaderImpl) GetArtifactName() string {
	return r.scanResult.ArtifactName
}
func (r *scanResultReaderImpl) WriteToCSV(buf io.Writer, includeHeader bool) error {
	return nil
}
func (r *scanResultReaderImpl) GetVulnerabilities() []types.VulnerabilityInfo {
	return r.scanResult.Results[0].Vulnerabilities
}

func TestWriteToJSON(t *testing.T) {
	// Create a type that implements the ScanResultReader interface

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

	reader := &scanResultReaderImpl{
		scanResult: scanResult,
	}

	var buf bytes.Buffer
	err := reader.WriteToJSON(&buf, []types.ScanResultReader{reader}) // Call method on reader
	require.NoError(t, err)

	var output map[string]interface{} // Adjust to match the expected structure
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	require.Equal(t, "test-artifact", output["ArtifactName"])

	results, ok := output["Results"].([]interface{})
	require.True(t, ok)

	firstResult, ok := results[0].(map[string]interface{})
	require.True(t, ok)

	vulnerabilities, ok := firstResult["Vulnerabilities"].([]interface{})
	require.True(t, ok)

	firstVulnerability, ok := vulnerabilities[0].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "CVE-2021-1234", firstVulnerability["VulnerabilityID"])
	assert.Equal(t, "test-package", firstVulnerability["PkgName"])
	assert.Equal(t, "1.0.0", firstVulnerability["InstalledVersion"])
	assert.Equal(t, "1.0.1", firstVulnerability["FixedVersion"])
	assert.Equal(t, "HIGH", firstVulnerability["Severity"])
	assert.Equal(t, "Test vulnerability", firstVulnerability["Description"])
}
