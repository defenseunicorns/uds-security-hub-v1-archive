package docker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RegistryCredentials stores credentials for a Docker registry.
type RegistryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenerateConfigText generates the Docker configuration as a JSON string.
func GenerateConfigText(credentialsMap map[string]RegistryCredentials) (string, error) {
	auths := make(map[string]map[string]string)
	for k, v := range credentialsMap {
		encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", v.Username, v.Password)))
		auths[k] = map[string]string{"auth": encoded}
	}

	config := map[string]interface{}{
		"auths": auths,
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("could not marshal Docker config: %w", err)
	}
	return string(configBytes), nil
}

// WriteConfigToTempDir writes the given Docker configuration text to a file in a temporary directory.
func WriteConfigToTempDir(configText string) (string, error) {
	tempDir, err := os.MkdirTemp("", "dockerconfig")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}

	configPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		return "", fmt.Errorf("could not write Docker config to file: %w", err)
	}

	return configPath, nil
}
