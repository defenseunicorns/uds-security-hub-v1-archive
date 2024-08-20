package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/defenseunicorns/uds-security-hub/internal/docker"
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
		Short: "Scan will scan a zarf package for vulnerabilities and generate a report with Trivy.",
		Long:  "Scan is a tool for scanning zarf packages for vulnerabilities and generating a report with Trivy",
		RunE:  runScanner, // Use RunE instead of Run to handle errors
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Check if Trivy is installed
			if _, err := exec.LookPath("trivy"); err != nil {
				return fmt.Errorf("trivy is not installed: %w", err)
			}

			// Check if either remote or local scan options are provided
			packagePath, _ := cmd.Flags().GetString("package-path") //nolint:errcheck
			if packagePath == "" {
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
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringSliceP("registry-creds", "r", []string{},
		`List of registry credentials in the format 'registry:username:password'. 
Example: 'registry1.dso.mil:myuser:mypassword'`)
	rootCmd.PersistentFlags().StringP("org", "o", "defenseunicorns", "Organization name")
	rootCmd.PersistentFlags().StringP("package-name", "n", "", "Package Name: packages/uds/gitlab-runner")
	rootCmd.PersistentFlags().StringP("tag", "g", "", "Tag name (e.g.  16.10.0-uds.0-upstream)")
	rootCmd.PersistentFlags().StringP("output-file", "f", "", "Output file for CSV results")
	rootCmd.PersistentFlags().StringP("package-path", "p", "", `Path to the local zarf package. 
This is for local scanning and not fetching from a remote registry.`)
	rootCmd.PersistentFlags().StringP("scanner-type", "s", "rootfs", "Trivy scanner type. options: sbom|rootfs")
	rootCmd.PersistentFlags().StringP("offline-db-path", "d", "", `Path to the offline DB to use for the scan. 
This is for local scanning and not fetching from a remote registry.
This should have all the files extracted from the trivy-db image and ran once before running the scan.`)

	return rootCmd
}

// runScanner is the main entry point for the scanner.
func runScanner(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	logger := log.NewLogger(ctx)
	org, _ := cmd.Flags().GetString("org")                           //nolint:errcheck
	packageName, _ := cmd.Flags().GetString("package-name")          //nolint:errcheck
	tag, _ := cmd.Flags().GetString("tag")                           //nolint:errcheck
	outputFile, _ := cmd.Flags().GetString("output-file")            //nolint:errcheck
	registryCreds, _ := cmd.Flags().GetStringSlice("registry-creds") //nolint:errcheck
	packagePath, _ := cmd.Flags().GetString("package-path")          //nolint:errcheck
	scannerType, _ := cmd.Flags().GetString("scanner-type")          //nolint:errcheck
	offlineDBPath, _ := cmd.Flags().GetString("offline-db-path")     //nolint:errcheck

	parsedCreds := docker.ParseCredentials(registryCreds)

	factory := &scan.ScannerFactoryImpl{}
	scanner, err := factory.CreateScanner(
		ctx,
		logger,
		org,
		packageName,
		tag,
		packagePath,
		offlineDBPath,
		parsedCreds,
		scannerType == "sbom",
	)
	if err != nil {
		return fmt.Errorf("error creating scanner: %w", err)
	}

	results, err := scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("error scanning: %w", err)
	}

	output := os.Stdout
	if outputFile != "" {
		var err error
		output, err = os.OpenFile(outputFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("error creating output csv: %w", err)
		}
	}

	for i, v := range results {
		r, err := scanner.ScanResultReader(v)
		if err != nil {
			return fmt.Errorf("error reading scan result: %w", err)
		}

		if err := r.WriteToCSV(output, i == 0); err != nil {
			return fmt.Errorf("failed to write to csv: %w", err)
		}
	}

	return nil
}
