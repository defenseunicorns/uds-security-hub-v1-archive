package types

// CommandExecutor is an interface for executing commands.
type CommandExecutor interface {
	// ExecuteCommand executes a command with the given name, arguments, and environment variables.
	// It returns the standard output, standard error, and any error that occurred during execution.
	ExecuteCommand(name string, args []string, env []string) (stdout string, stderr string, err error)
}
