package gitlab

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/cmd/trajan/gitlab/enumerate"
	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var GitLabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Trajan - GitLab CI",
	Long:  `Trajan - GitLab CI`,
}

func init() {
	GitLabCmd.AddCommand(enumerate.NewEnumerateCmd())
	GitLabCmd.AddCommand(scanCmd)
	GitLabCmd.AddCommand(attackCmd)

	// GitLab-specific flags
	GitLabCmd.PersistentFlags().SortFlags = false
	GitLabCmd.PersistentFlags().String("url", "", "base URL for self-hosted GitLab (e.g., https://gitlab.example.com)")
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "gitlab")
}
