package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/defenseunicorns/uds-security-hub/internal/log"
	"github.com/defenseunicorns/uds-security-hub/pkg/scan"
)

// errFlagRetrieval is the error message for when a flag cannot be retrieved.
var errFlagRetrieval = errors.New("error getting flag")

// errRequiredFlagEmpty is the error message for a required flag that is empty.
var errRequiredFlagEmpty = errors.New("is required and cannot be empty")

// Execute is the main entry point for the scanner.
func Execute(args []string) {
	rootCmd := newRootCmd()
	rootCmd.SetArgs(args) // Set the arguments
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd creates the root command for the scanner.
func newRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "scan",
		Short: "[ALPHA] Scan will scan a zarf package for vulnerabilities and generate a report with Trivy.",
		Long:  "[ALPHA] Scan is a tool for scanning zarf packages for vulnerabilities and generating a report with Trivy",
		RunE:  runScanner, // Use RunE instead of Run to handle errors
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Check if Trivy is installed
			if _, err := exec.LookPath("trivy"); err != nil {
				return fmt.Errorf("trivy is not installed: %w", err)
			}

			requiredFlags := []string{"org", "package-name", "tag"}
			for _, flag := range requiredFlags {
				value, err := cmd.Flags().GetString(flag)
				if err != nil {
					return fmt.Errorf("%w: %s: %w", errFlagRetrieval, flag, err)
				}
				if value == "" {
					return fmt.Errorf("%s %w", flag, errRequiredFlagEmpty)
				}
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringP("docker-username", "u", "",
		"Optional: Docker username for registry access, accepts CSV values")
	rootCmd.PersistentFlags().StringP("docker-password", "p", "",
		"Optional: Docker password for registry access, accepts CSV values")
	rootCmd.PersistentFlags().StringP("org", "o", "defenseunicorns", "Organization name")
	rootCmd.PersistentFlags().StringP("package-name", "n", "", "Package Name: packages/uds/gitlab-runner")
	rootCmd.PersistentFlags().StringP("tag", "g", "", "Tag name (e.g.  16.10.0-uds.0-upstream)")
	rootCmd.PersistentFlags().StringP("output-file", "f", "", "Output file for CSV results")

	return rootCmd
}

// runScanner is the main entry point for the scanner.
func runScanner(cmd *cobra.Command, _ []string) error {
	logger := log.NewLogger(context.Background())
	org, _ := cmd.Flags().GetString("org")                  //nolint:errcheck
	packageName, _ := cmd.Flags().GetString("package-name") //nolint:errcheck
	tag, _ := cmd.Flags().GetString("tag")                  //nolint:errcheck
	outputFile, _ := cmd.Flags().GetString("output-file")   //nolint:errcheck

	scanner, err := scan.New(context.Background(), logger, "")
	if err != nil {
		return fmt.Errorf("error creating scanner: %w", err)
	}
	results, err := scanner.ScanZarfPackage(org, packageName, tag)
	if err != nil {
		return fmt.Errorf("error scanning package: %w", err)
	}
	var combinedCSV string
	for _, v := range results {
		r, err := scanner.ScanResultReader(v)
		if err != nil {
			return fmt.Errorf("error scanning: %w", err)
		}

		csv := r.GetResultsAsCSV()
		combinedCSV += csv
	}

	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(combinedCSV), 0o600)
		if err != nil {
			return fmt.Errorf("error writing to file: %w", err)
		}
		logger.Info(fmt.Sprintf("Results written to %s", outputFile))
	} else {
		logger.Info(combinedCSV)
	}
	return nil
}
