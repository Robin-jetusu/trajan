package enumerate

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate GitLab resources and attack surface",
	Long: `Trajan - GitLab CI - Enumerate

Capabilities:
  * Token validation and scope analysis
  * Project discovery and access mapping
  * Group hierarchy and shared access
  * CI/CD variable (secrets) enumeration
  * Runner enumeration and workflow tag analysis
  * Branch protection rule analysis

Authentication:
  Tokens can be provided via --token flag or environment variables:
    GITLAB_TOKEN, GL_TOKEN`,
}

func init() {
	enumerateCmd.AddCommand(tokenCmd)
	enumerateCmd.AddCommand(projectsCmd)
	enumerateCmd.AddCommand(groupsCmd)
	enumerateCmd.AddCommand(secretsCmd)
	enumerateCmd.AddCommand(branchProtectionsCmd)
	enumerateCmd.AddCommand(runnersCmd)
}

func NewEnumerateCmd() *cobra.Command {
	return enumerateCmd
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "gitlab")
}

func getGitLabURL(cmd *cobra.Command) string {
	url, _ := cmd.Root().PersistentFlags().GetString("url")
	if url == "" {
		// Check parent gitlab command for --url flag
		for p := cmd.Parent(); p != nil; p = p.Parent() {
			if u, err := p.Flags().GetString("url"); err == nil && u != "" {
				return u
			}
		}
	}
	return url
}
