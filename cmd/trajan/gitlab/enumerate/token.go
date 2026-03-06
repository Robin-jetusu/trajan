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

var tokenOutputFile string

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Validate and analyze GitLab token capabilities",
	Long: `Trajan - GitLab CI - Enumerate

Validate and inspect the provided GitLab token.
Reports token type (Personal, Project, or Group Access Token), scopes, expiration,
admin status, accessible groups, and current rate limit status.`,
	RunE: runTokenEnumerate,
}

func init() {
	tokenCmd.Flags().SortFlags = false
	tokenCmd.Flags().StringVar(&tokenOutputFile, "output-file", "",
		"save output to file")
}

func runTokenEnumerate(cmd *cobra.Command, args []string) error {
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
		fmt.Fprintf(os.Stderr, "Validating token and enumerating groups...\n")
	}

	result, err := glPlatform.EnumerateToken(ctx)
	if err != nil {
		return fmt.Errorf("enumerating token: %w", err)
	}

	switch output {
	case "json":
		return outputTokenJSON(result, tokenOutputFile)
	default:
		return outputTokenConsole(result)
	}
}
