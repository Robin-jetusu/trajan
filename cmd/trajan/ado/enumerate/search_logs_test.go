package enumerate

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestNewSearchLogsCmd(t *testing.T) {
	cmd := newSearchLogsCmd()

	if cmd == nil {
		t.Fatal("newSearchLogsCmd() returned nil")
	}

	if cmd.Use != "logs" {
		t.Errorf("expected Use='logs', got %q", cmd.Use)
	}

	// Verify required flags
	projectFlag := cmd.Flags().Lookup("project")
	if projectFlag == nil {
		t.Error("--project flag not found")
	}

	queryFlag := cmd.Flags().Lookup("query")
	if queryFlag == nil {
		t.Error("--query flag not found")
	}

	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Error("--limit flag not found")
	}
}

func TestNewSearchLogsCmd_Subcommand(t *testing.T) {
	// Verify the command can be registered as a subcommand
	parent := &cobra.Command{Use: "search"}
	parent.AddCommand(newSearchLogsCmd())

	subCmd, _, err := parent.Find([]string{"logs"})
	if err != nil {
		t.Fatalf("failed to find logs subcommand: %v", err)
	}

	if subCmd.Use != "logs" {
		t.Errorf("expected subcommand Use='logs', got %q", subCmd.Use)
	}
}
