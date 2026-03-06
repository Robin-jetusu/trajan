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
	secretsProject    string
	secretsGroup      string
	secretsOutputFile string
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Enumerate CI/CD variables (secrets)",
	Long: `Trajan - GitLab CI - Enumerate

Enumerate CI/CD variables (secrets) at the project, group, or instance level.
Requires Maintainer+ access; unlike GitHub, GitLab returns actual secret values.
Console output shows variable names only — use --output json to retrieve full values.`,
	RunE: runSecretsEnumerate,
}

func init() {
	secretsCmd.Flags().SortFlags = false
	secretsCmd.Flags().StringVar(&secretsProject, "project", "", "project to enumerate (group/project)")
	secretsCmd.Flags().StringVar(&secretsGroup, "group", "", "group to enumerate")
	secretsCmd.Flags().StringVar(&secretsOutputFile, "output-file", "", "save output to file")
}

func runSecretsEnumerate(cmd *cobra.Command, args []string) error {
	token := getToken(cmd)
	if token == "" {
		return fmt.Errorf("no token provided (use --token or set GITLAB_TOKEN/GL_TOKEN env var)")
	}

	output := cmdutil.GetOutput(cmd)

	var target platforms.Target
	switch {
	case secretsProject != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: secretsProject}
	case secretsGroup != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: secretsGroup}
	default:
		return fmt.Errorf("must specify --project or --group")
	}

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
		fmt.Fprintf(os.Stderr, "Enumerating secrets...\n")
	}

	result, err := glPlatform.EnumerateSecrets(ctx, target)
	if err != nil {
		return fmt.Errorf("enumerating secrets: %w", err)
	}

	switch output {
	case "json":
		return outputSecretsJSON(result, secretsOutputFile)
	default:
		return outputSecretsConsole(result)
	}
}
