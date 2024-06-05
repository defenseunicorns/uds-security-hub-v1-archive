package main

import (
	"os"

	"github.com/defenseunicorns/uds-security-hub/cmd"
)

// main function remains to call Execute.
func main() {
	cmd.Execute(os.Args[1:])
}
