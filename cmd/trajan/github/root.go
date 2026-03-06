package github

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var GitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Trajan - GitHub",
	Long:  `Trajan - GitHub`,
}

func init() {
	GitHubCmd.AddCommand(enumerateCmd)
	GitHubCmd.AddCommand(scanCmd)
	GitHubCmd.AddCommand(attackCmd)
	GitHubCmd.AddCommand(retrieveCmd)
	GitHubCmd.AddCommand(searchCmd)
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "github")
}
