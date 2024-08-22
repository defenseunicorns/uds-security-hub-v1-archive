package scan

import (
	"bytes"
	"encoding/json"
	"testing"

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

	reader := scanResultReader{
		scanResult: scanResult,
	}

	var buf bytes.Buffer
	err := reader.WriteToJSON(&buf)
	require.NoError(t, err)

	var output []map[string]string
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	require.Len(t, output, 1)
	assert.Equal(t, "test-artifact", output[0]["ArtifactName"])
	assert.Equal(t, "CVE-2021-1234", output[0]["VulnerabilityID"])
	assert.Equal(t, "test-package", output[0]["PkgName"])
	assert.Equal(t, "1.0.0", output[0]["InstalledVersion"])
	assert.Equal(t, "1.0.1", output[0]["FixedVersion"])
	assert.Equal(t, "HIGH", output[0]["Severity"])
	assert.Equal(t, "Test vulnerability", output[0]["Description"])
}
