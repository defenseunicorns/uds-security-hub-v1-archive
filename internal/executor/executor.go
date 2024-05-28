package executor

import (
	"bytes"
	"context"
	"os/exec"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

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

func NewCommandExecutor(ctx context.Context) types.CommandExecutor {
	return &RealCommandExecutor{ctx: ctx}
}
