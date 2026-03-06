package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Trajan - Version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("trajan version %s\n", Version)
		fmt.Printf("  Git commit: %s\n", GitCommit)
		fmt.Printf("  Build date: %s\n", BuildDate)
	},
}
