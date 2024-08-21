package docker

import (
	"strings"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// RegistryCredentials stores credentials for a Docker registry.
type RegistryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
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
