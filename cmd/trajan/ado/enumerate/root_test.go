package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnumerateCmdHasSubcommands(t *testing.T) {
	cmd := NewEnumerateCmd()

	require.NotNil(t, cmd)
	assert.Equal(t, "enumerate", cmd.Use)

	// Verify subcommands exist
	subCommands := cmd.Commands()
	require.Greater(t, len(subCommands), 0, "enumerate should have subcommands")

	// Verify auth, list, search subcommands are present
	subCmdNames := make(map[string]bool)
	for _, subCmd := range subCommands {
		subCmdNames[subCmd.Name()] = true
	}

	assert.True(t, subCmdNames["token"], "should have 'token' subcommand")
	assert.True(t, subCmdNames["projects"], "should have 'projects' subcommand")
	assert.True(t, subCmdNames["repos"], "should have 'repos' subcommand")
	assert.True(t, subCmdNames["pipelines"], "should have 'pipelines' subcommand")
	assert.True(t, subCmdNames["search"], "should have 'search' subcommand")
}

func TestNewEnumerateCmdFlags(t *testing.T) {
	cmd := NewEnumerateCmd()

	// Verify shared flags exist
	flags := cmd.PersistentFlags()

	assert.NotNil(t, flags.Lookup("platform"))
	assert.NotNil(t, flags.Lookup("token"))
	assert.NotNil(t, flags.Lookup("org"))
	assert.NotNil(t, flags.Lookup("url"))
	assert.NotNil(t, flags.Lookup("output"))
	assert.NotNil(t, flags.Lookup("project"))
}
