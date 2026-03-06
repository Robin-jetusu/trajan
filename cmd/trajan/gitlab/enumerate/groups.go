package enumerate

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	_ "github.com/praetorian-inc/trajan/pkg/platforms/all"
)

var (
	groupsRecursive  bool
	groupsOutputFile string
)

var groupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Discover accessible groups and organizational structure",
	Long: `Trajan - GitLab CI - Enumerate

Discover accessible GitLab groups and their organizational hierarchy.
Reports access level per group and shared group access paths that may enable lateral movement.
Use --recursive to traverse subgroup hierarchies.`,
	RunE: runGroupsEnumerate,
}

func init() {
	groupsCmd.Flags().SortFlags = false
	groupsCmd.Flags().BoolVar(&groupsRecursive, "recursive", false, "enumerate subgroup hierarchy")
	groupsCmd.Flags().StringVar(&groupsOutputFile, "output-file", "", "save output to file")
}

func runGroupsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GITLAB_TOKEN/GL_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)
	ctx := context.Background()

	platform, err := registry.GetPlatform("gitlab")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:  token,
		GitLab: &platforms.GitLabAuth{Token: token},
	}
	if url := getGitLabURL(cmd); url != "" {
		config.BaseURL = url
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	glPlatform, ok := platform.(*gitlabplatform.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}

	if output == "console" {
		fmt.Fprintf(os.Stderr, "Enumerating groups...\n")
	}

	result, err := glPlatform.EnumerateGroups(ctx, groupsRecursive)
	if err != nil {
		return fmt.Errorf("enumerating groups: %w", err)
	}

	switch output {
	case "json":
		return outputGroupsJSON(result, groupsOutputFile)
	default:
		return outputGroupsConsole(result)
	}
}
