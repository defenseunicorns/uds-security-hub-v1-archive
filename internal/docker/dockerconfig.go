package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
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

// GenerateAndWriteDockerConfig creates and writes Docker configuration based on provided credentials.
func GenerateAndWriteDockerConfig(ctx context.Context, credentials []types.RegistryCredentials) (string, error) {
	credentialsMap := make(map[string]RegistryCredentials)
	for _, cred := range credentials {
		if cred.Username != "" && cred.Password != "" {
			credentialsMap[cred.RegistryURL] = RegistryCredentials{
				Username: cred.Username,
				Password: cred.Password,
			}
		}
	}

	configText, err := generateConfigText(credentialsMap)
	if err != nil {
		return "", fmt.Errorf("error generating Docker config: %w", err)
	}

	dockerConfigPath, err := writeConfigToTempDir(configText)
	if err != nil {
		return "", fmt.Errorf("error writing Docker config to temp dir: %w", err)
	}

	return filepath.Dir(dockerConfigPath), nil
}

// generateConfigText generates the Docker configuration as a JSON string.
func generateConfigText(credentialsMap map[string]RegistryCredentials) (string, error) {
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

// writeConfigToTempDir writes the given Docker configuration text to a file in a temporary directory.
func writeConfigToTempDir(configText string) (string, error) {
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

// ParseCredentials parses the given credentials into a slice of RegistryCredentials.
func ParseCredentials(creds []string) []types.RegistryCredentials {
	const (
		registryURLIndex = 0
		usernameIndex    = 1
		passwordIndex    = 2
		splitChar        = ":"
	)
	var result []types.RegistryCredentials
	for _, c := range creds {
		parts := strings.SplitN(c, splitChar, 3)
		if len(parts) == 3 {
			result = append(result, types.RegistryCredentials{
				RegistryURL: parts[registryURLIndex],
				Username:    parts[usernameIndex],
				Password:    parts[passwordIndex],
			})
		}
	}
	return result
}
