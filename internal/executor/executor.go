package executor

import (
	"bytes"
	"context"
	"os/exec"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// RealCommandExecutor is a struct that implements the CommandExecutor interface.
type RealCommandExecutor struct {
	ctx context.Context
}

// ExecuteCommand executes a command and returns the stdout, stderr, and error.
//
//nolint:gocritic
func (r *RealCommandExecutor) ExecuteCommand(name string, args []string,
	env []string) (stdout string, stderr string, err error) {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	return outb.String(), errb.String(), err
}

// NewCommandExecutor creates a new instance of the RealCommandExecutor.
func NewCommandExecutor(ctx context.Context) types.CommandExecutor {
	return &RealCommandExecutor{ctx: ctx}
}
