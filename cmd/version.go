package cmd

import (
	"runtime/debug"
)

// Version can be set via:
// -ldflags="-X 'github.com/defenseunicorns/uds-security-hub/cmd/version.Version=$TAG'"
var Version string

func init() {
	if Version == "" {
		i, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		Version = i.Main.Version
	}
}
