package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestNewRootCmd tests the newRootCmd function.
func TestNewRootCmd(t *testing.T) {
	cmd := newRootCmd()

	if diff := cmp.Diff("scan", cmd.Use); diff != "" {
		t.Errorf("cmd.Use mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("Scan is a tool for scanning packages", cmd.Short); diff != "" {
		t.Errorf("cmd.Short mismatch (-want +got):\n%s", diff)
	}

	flags := []string{"docker-username", "docker-password", "ghcr-token", "org", "package-name", "tag", "output-file"}
	for _, flag := range flags {
		f := cmd.PersistentFlags().Lookup(flag)
		if f == nil {
			t.Errorf("flag %s should be defined", flag)
		}
	}
}

// TestPreRunE_MissingRequiredFlags tests the preRunE function with missing required flags.
func TestPreRunE_MissingRequiredFlags(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--org", "test-org", "--package-name", "test-package"})

	err := cmd.Execute()
	if err == nil {
		t.Errorf("expected an error but got nil")
	} else if diff := cmp.Diff("tag is required and cannot be empty", err.Error()); diff != "" {
		t.Errorf("error message mismatch (-want +got):\n%s", diff)
	}
}

// TestPreRunE_MissingOrgFlag tests the preRunE function with missing the org flag.
func TestPreRunE_MissingOrgFlag(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--package-name", "test-package", "--tag", "test-tag"})

	err := cmd.Execute()
	if err == nil {
		t.Errorf("expected an error but got nil")
	} else if diff := cmp.Diff("org is required and cannot be empty", err.Error()); diff != "" {
		t.Errorf("error message mismatch (-want +got):\n%s", diff)
	}
}

// TestPreRunE_InvalidFlag tests the preRunE function with an invalid flag.
func TestPreRunE_InvalidFlag(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--invalid-flag", "value"})

	err := cmd.Execute()
	if err == nil {
		t.Errorf("expected an error but got nil")
	} else if diff := cmp.Diff("unknown flag: --invalid-flag", err.Error()); diff != "" {
		t.Errorf("error message mismatch (-want +got):\n%s", diff)
	}
}
