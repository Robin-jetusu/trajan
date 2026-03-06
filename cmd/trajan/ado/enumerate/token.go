package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	azdoProbe "github.com/praetorian-inc/trajan/pkg/azuredevops/tokenprobe"
	"github.com/praetorian-inc/trajan/pkg/output"
)

var tokenDetailed bool

type permissionResult struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type projectPerms struct {
	ProjectName string             `json:"project"`
	ProjectID   string             `json:"project_id"`
	Build       []permissionResult `json:"build"`
	Git         []permissionResult `json:"git"`
}

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Validate PAT and enumerate accessible resources",
		Long: `Trajan - Azure DevOps - Enumerate

Validate the provided PAT and enumerate accessible Azure DevOps resources.

Checks PAT validity, user information, detected capabilities, and resource
counts in a single pass. Use --detailed to also show per-project Build and
Git permission checks for every accessible project.`,
		RunE: runTokenEnumerate,
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVar(&tokenDetailed, "detailed", false, "Include per-project Build and Git permissions")

	return cmd
}

func runTokenEnumerate(cmd *cobra.Command, args []string) error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required")
	}

	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	prober := azdoProbe.NewProber(client)
	prober.SetFeedsClient(client.FeedsClient())
	probeResult, err := prober.Probe(ctx)
	if err != nil {
		return fmt.Errorf("probing PAT: %w", err)
	}

	// GetConnectionData for service owner (user info already in probeResult.User).
	// Only call when PAT is valid; if invalid, render functions exit early anyway.
	var connData *azuredevops.ConnectionData
	if probeResult.Valid {
		connData, err = client.GetConnectionData(ctx)
		if err != nil {
			return fmt.Errorf("getting connection data: %w", err)
		}
	} else {
		connData = &azuredevops.ConnectionData{}
	}

	switch enumOutput {
	case "json":
		return renderTokenJSON(ctx, client, probeResult, connData)
	case "csv":
		return renderTokenCSV(ctx, client, probeResult, connData)
	default:
		return renderTokenConsole(ctx, client, probeResult, connData)
	}
}

func renderTokenConsole(ctx context.Context, client *azuredevops.Client, result *azdoProbe.ProbeResult, connData *azuredevops.ConnectionData) error {
	if !result.Valid {
		fmt.Println("PAT is invalid or has no permissions")
		return nil
	}

	fmt.Println("PAT is valid")
	fmt.Println()

	if result.User != nil {
		fmt.Printf("User:          %s\n", result.User.DisplayName)
		if result.User.Email != "" {
			fmt.Printf("Email:         %s\n", result.User.Email)
		}
		fmt.Printf("User ID:       %s\n", result.User.ID)
	}
	fmt.Printf("Organization:  %s\n", enumOrg)
	fmt.Printf("Service Owner: %s\n", connData.LocationServiceData.ServiceOwner)

	fmt.Println("\nDetected Capabilities:")
	if len(result.Capabilities) == 0 {
		fmt.Println("  (none detected)")
	} else {
		for _, cap := range result.Capabilities {
			fmt.Printf("  %s\n", cap)
		}
	}

	fmt.Println("\nAccess Summary:")
	fmt.Printf("  Projects:            %d\n", result.ProjectCount)
	fmt.Printf("  Repositories:        %d\n", result.RepositoryCount)
	fmt.Printf("  Pipelines:           %d\n", result.PipelineCount)
	fmt.Printf("  Agent Pools:         %d\n", result.AgentPoolCount)
	fmt.Printf("  Variable Groups:     %d\n", result.VariableGroupCount)
	fmt.Printf("  Service Connections: %d\n", result.ServiceConnectionCount)
	fmt.Printf("  Artifact Feeds:      %d\n", result.ArtifactFeedCount)

	if result.HasHighValueAccess() {
		fmt.Println("\nHigh-value access detected")
	}

	if tokenDetailed {
		fmt.Println()
		return printProjectPermissions(ctx, client)
	}

	return nil
}

func renderTokenJSON(ctx context.Context, client *azuredevops.Client, result *azdoProbe.ProbeResult, connData *azuredevops.ConnectionData) error {
	capsStr := make([]string, len(result.Capabilities))
	for i, c := range result.Capabilities {
		capsStr[i] = string(c)
	}

	out := map[string]interface{}{
		"valid":                  result.Valid,
		"organization":           enumOrg,
		"serviceOwner":           connData.LocationServiceData.ServiceOwner,
		"capabilities":           capsStr,
		"projectCount":           result.ProjectCount,
		"repositoryCount":        result.RepositoryCount,
		"pipelineCount":          result.PipelineCount,
		"agentPoolCount":         result.AgentPoolCount,
		"variableGroupCount":     result.VariableGroupCount,
		"serviceConnectionCount": result.ServiceConnectionCount,
		"artifactFeedCount":      result.ArtifactFeedCount,
		"hasHighValueAccess":     result.HasHighValueAccess(),
	}

	if result.User != nil {
		out["user"] = map[string]string{
			"displayName": result.User.DisplayName,
			"email":       result.User.Email,
			"id":          result.User.ID,
		}
	}

	if tokenDetailed {
		perms, err := collectProjectPermissions(ctx, client)
		if err != nil {
			return err
		}
		out["permissions"] = perms
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderTokenCSV(ctx context.Context, client *azuredevops.Client, result *azdoProbe.ProbeResult, connData *azuredevops.ConnectionData) error {
	if tokenDetailed {
		perms, err := collectProjectPermissions(ctx, client)
		if err != nil {
			return err
		}
		headers := []string{"Project", "Namespace", "Permission", "Allowed"}
		var rows [][]string
		for _, pp := range perms {
			for _, p := range pp.Build {
				rows = append(rows, []string{pp.ProjectName, "Build", p.Name, formatBool(p.Allowed)})
			}
			for _, p := range pp.Git {
				rows = append(rows, []string{pp.ProjectName, "Git Repositories", p.Name, formatBool(p.Allowed)})
			}
		}
		return output.RenderCSV(os.Stdout, headers, rows)
	}

	validStr := "invalid"
	if result.Valid {
		validStr = "valid"
	}

	headers := []string{"Field", "Value"}
	var rows [][]string
	rows = append(rows, []string{"token_status", validStr})
	if result.User != nil {
		rows = append(rows, []string{"user", result.User.DisplayName})
		rows = append(rows, []string{"user_id", result.User.ID})
	}
	rows = append(rows, []string{"organization", enumOrg})
	rows = append(rows, []string{"service_owner", connData.LocationServiceData.ServiceOwner})
	for _, cap := range result.Capabilities {
		rows = append(rows, []string{"capability", string(cap)})
	}
	rows = append(rows, []string{"projects", fmt.Sprintf("%d", result.ProjectCount)})
	rows = append(rows, []string{"repositories", fmt.Sprintf("%d", result.RepositoryCount)})
	rows = append(rows, []string{"pipelines", fmt.Sprintf("%d", result.PipelineCount)})
	rows = append(rows, []string{"agent_pools", fmt.Sprintf("%d", result.AgentPoolCount)})
	rows = append(rows, []string{"variable_groups", fmt.Sprintf("%d", result.VariableGroupCount)})
	rows = append(rows, []string{"service_connections", fmt.Sprintf("%d", result.ServiceConnectionCount)})
	rows = append(rows, []string{"artifact_feeds", fmt.Sprintf("%d", result.ArtifactFeedCount)})
	return output.RenderCSV(os.Stdout, headers, rows)
}

func collectProjectPermissions(ctx context.Context, client *azuredevops.Client) ([]projectPerms, error) {
	projects, err := client.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}

	var allPerms []projectPerms

	for _, proj := range projects {
		pp := projectPerms{
			ProjectName: proj.Name,
			ProjectID:   proj.ID,
		}

		buildChecks := []struct {
			bit  int
			name string
		}{
			{buildPermViewBuilds, "View builds"},
			{buildPermQueueBuilds, "Queue builds"},
			{buildPermViewDefinitions, "View build definition"},
			{buildPermEditBuildDefinition, "Edit build definition"},
			{buildPermDeleteBuilds, "Delete builds"},
			{buildPermStopBuilds, "Stop builds"},
			{buildPermAdministerPermissions, "Administer build permissions"},
		}

		for _, check := range buildChecks {
			allowed, err := client.CheckPermission(ctx, buildNamespaceID, check.bit, proj.ID)
			if err != nil {
				continue
			}
			pp.Build = append(pp.Build, permissionResult{Name: check.name, Allowed: allowed})
		}

		gitChecks := []struct {
			bit  int
			name string
		}{
			{gitPermAdminister, "Administer"},
			{gitPermRead, "Read"},
			{gitPermContribute, "Contribute"},
			{gitPermForcePush, "Force push"},
			{gitPermCreateBranch, "Create branch"},
			{gitPermBypassPoliciesPush, "Bypass policies when pushing"},
			{gitPermContributeToPR, "Contribute to pull requests"},
			{gitPermBypassPoliciesPR, "Bypass policies when completing PR"},
		}

		for _, check := range gitChecks {
			allowed, err := client.CheckPermission(ctx, gitNamespaceID, check.bit, "repoV2/"+proj.ID)
			if err != nil {
				continue
			}
			pp.Git = append(pp.Git, permissionResult{Name: check.name, Allowed: allowed})
		}

		allPerms = append(allPerms, pp)
	}

	return allPerms, nil
}

func printProjectPermissions(ctx context.Context, client *azuredevops.Client) error {
	allPerms, err := collectProjectPermissions(ctx, client)
	if err != nil {
		return err
	}

	for _, pp := range allPerms {
		fmt.Printf("=== %s ===\n", pp.ProjectName)
		fmt.Println("\nBuild Permissions:")
		for _, p := range pp.Build {
			fmt.Printf("  %-40s %s\n", p.Name, formatBool(p.Allowed))
		}
		fmt.Println("\nGit Permissions:")
		for _, p := range pp.Git {
			fmt.Printf("  %-40s %s\n", p.Name, formatBool(p.Allowed))
		}
		fmt.Println()
	}

	return nil
}
