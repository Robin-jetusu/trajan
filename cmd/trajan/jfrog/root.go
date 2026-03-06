package jfrog

import (
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
)

var JFrogCmd = &cobra.Command{
	Use:   "jfrog",
	Short: "Trajan - JFrog",
	Long:  `Trajan - JFrog`,
}

func init() {
	JFrogCmd.PersistentFlags().SortFlags = false
	JFrogCmd.PersistentFlags().String("url", "", "JFrog instance URL (e.g., https://acme.jfrog.io)")
	JFrogCmd.AddCommand(scanCmd)
}

func getToken(cmd *cobra.Command) string {
	return cmdutil.GetTokenForPlatform(cmd, "jfrog")
}
