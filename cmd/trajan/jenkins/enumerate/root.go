package enumerate

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate Jenkins resources and attack surface",
	Long: `Trajan - Jenkins - Enumerate

Enumerate and discover Jenkins resources accessible with the current credentials.

Subcommands:
  access   - Probe access level, user identity, and server info
  jobs     - List all accessible jobs and folders
  nodes    - List build agents/nodes
  plugins  - List installed plugins and versions`,
}

func init() {
	enumerateCmd.AddCommand(accessCmd)
	enumerateCmd.AddCommand(jobsCmd)
	enumerateCmd.AddCommand(nodesCmd)
	enumerateCmd.AddCommand(pluginsCmd)
}

func NewEnumerateCmd() *cobra.Command {
	return enumerateCmd
}

func getToken(cmd *cobra.Command) string {
	if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
		return p
	}
	return cmdutil.GetTokenForPlatform(cmd, "jenkins")
}

func getUsername(cmd *cobra.Command) string {
	if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
		return u
	}
	return cmdutil.GetUsernameForPlatform(cmd, "jenkins")
}
