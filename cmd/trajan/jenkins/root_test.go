package jenkins

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTokenTestRoot builds a minimal command tree for testing getToken.
// It wires a root "trajan" command (with --token) and a "jenkins" subcommand
// (with --username and --password), matching the shape the real CLI uses.
//
// The jenkins command is given a no-op RunE so that cobra parses and merges
// persistent flags before the handler runs, which mirrors production usage
// where getToken is always called from inside a RunE.
func newTokenTestRoot(capturer *string) *cobra.Command {
	root := &cobra.Command{Use: "trajan"}
	root.PersistentFlags().String("token", "", "")

	jenkinsCmd := &cobra.Command{
		Use: "jenkins",
		RunE: func(cmd *cobra.Command, args []string) error {
			*capturer = getToken(cmd)
			return nil
		},
	}
	jenkinsCmd.PersistentFlags().String("username", "", "")
	jenkinsCmd.PersistentFlags().String("password", "", "")

	root.AddCommand(jenkinsCmd)
	return root
}

// TestGetToken_PasswordFlagTakesPrecedence verifies that --password wins over
// --token when both flags are explicitly set. This exercises the first branch
// of getToken's precedence chain.
func TestGetToken_PasswordFlagTakesPrecedence(t *testing.T) {
	var captured string
	root := newTokenTestRoot(&captured)
	root.SetArgs([]string{"jenkins", "--password=my-password", "--token=my-token"})

	// --token is a persistent flag on root, not jenkins, so we set it directly.
	require.NoError(t, root.PersistentFlags().Set("token", "my-token"))

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "my-password", captured)
}

// TestGetToken_FallsThroughToGlobalToken verifies that when --password is not
// set, getToken falls through to the root --token flag for backward
// compatibility.
func TestGetToken_FallsThroughToGlobalToken(t *testing.T) {
	var captured string
	root := newTokenTestRoot(&captured)
	root.SetArgs([]string{"jenkins"})
	require.NoError(t, root.PersistentFlags().Set("token", "my-token"))
	// --password intentionally left unset

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "my-token", captured)
}

// TestGetToken_FallsThroughToEnvVar verifies that when neither --password nor
// --token flags are set, getToken reads from the JENKINS_TOKEN environment
// variable.
func TestGetToken_FallsThroughToEnvVar(t *testing.T) {
	t.Setenv("JENKINS_TOKEN", "env-token")

	var captured string
	root := newTokenTestRoot(&captured)
	root.SetArgs([]string{"jenkins"})
	// No flags set; env var should win.

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "env-token", captured)
}
