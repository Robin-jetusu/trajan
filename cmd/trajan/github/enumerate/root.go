package enumerate

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate GitHub resources and attack surface",
	Long: `Trajan - GitHub - Enumerate

Enumerate and discover GitHub resources accessible to the authenticated token.

The enumerate command provides detailed reconnaissance capabilities including:
  - Token validation and accessible organizations
  - Repository discovery and access mapping
  - Secrets enumeration (Actions secrets and workflow references)`,
}

func init() {
	enumerateCmd.AddCommand(tokenCmd)
	enumerateCmd.AddCommand(reposCmd)
	enumerateCmd.AddCommand(secretsCmd)
	// TODO: Add other subcommands (workflows, graph, all)
}

func NewEnumerateCmd() *cobra.Command {
	return enumerateCmd
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "github")
}
