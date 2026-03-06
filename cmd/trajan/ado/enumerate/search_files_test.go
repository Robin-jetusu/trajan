package enumerate

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestNewSearchFilesCmd(t *testing.T) {
	cmd := newSearchFilesCmd()

	if cmd == nil {
		t.Fatal("newSearchFilesCmd() returned nil")
	}

	if cmd.Use != "files" {
		t.Errorf("expected Use='files', got %q", cmd.Use)
	}

	// Verify required flags
	queryFlag := cmd.Flags().Lookup("query")
	if queryFlag == nil {
		t.Error("--query flag not found")
	}

	// Verify optional flags
	projectFlag := cmd.Flags().Lookup("project")
	if projectFlag == nil {
		t.Error("--project flag not found (should be optional)")
	}
}

func TestNewSearchFilesCmd_Subcommand(t *testing.T) {
	// Verify the command can be registered as a subcommand
	parent := &cobra.Command{Use: "search"}
	parent.AddCommand(newSearchFilesCmd())

	subCmd, _, err := parent.Find([]string{"files"})
	if err != nil {
		t.Fatalf("failed to find files subcommand: %v", err)
	}

	if subCmd.Use != "files" {
		t.Errorf("expected subcommand Use='files', got %q", subCmd.Use)
	}
}
