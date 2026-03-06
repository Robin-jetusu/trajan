package aipromptinjection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/attacks/shared/augustusprobe"
	"github.com/praetorian-inc/trajan/pkg/attacks/shared/payloads"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/github/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("github", "ai-prompt-injection", func() attacks.AttackPlugin {
		return New()
	})
}

// aiVulnTypes lists all AI-related vulnerability types that trigger this plugin.
var aiVulnTypes = detections.AIVulnTypes

// deliveryMethod represents how adversarial prompts are delivered.
type deliveryMethod string

const (
	deliveryPR      deliveryMethod = "pull_request"
	deliveryIssue   deliveryMethod = "issue"
	deliveryComment deliveryMethod = "issue_comment"
)

// defaultMaxPrompts is the default limit on prompts delivered per attack.
const defaultMaxPrompts = 5

// Plugin implements AI prompt injection attack for GitHub repositories.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new AI prompt injection attack plugin.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ai-prompt-injection",
			"Deliver adversarial prompts via PRs/issues to test AI code review tools",
			"github",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack always returns false — this plugin should only be invoked explicitly
// via --plugin ai-prompt-injection, not auto-triggered during broad attack runs.
func (p *Plugin) CanAttack(_ []detections.Finding) bool {
	return false
}

// maxPromptsUpperBound prevents unreasonable max_prompts values.
const maxPromptsUpperBound = 50

// Execute delivers adversarial prompts via the appropriate channel.
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}
	defer func() {
		audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	}()

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

	// Determine delivery method and which vuln types are present
	delivery, vulnTypes := analyzeFindings(opts.Findings)

	// Allow ExtraOpts overrides
	maxPrompts := defaultMaxPrompts
	if v, ok := opts.ExtraOpts["max_prompts"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxPrompts = n
		}
	}
	if maxPrompts > maxPromptsUpperBound {
		maxPrompts = maxPromptsUpperBound
	}
	if v, ok := opts.ExtraOpts["delivery"]; ok {
		d, err := parseDeliveryOverride(v)
		if err != nil {
			result.Success = false
			result.Message = err.Error()
			return result, err
		}
		delivery = d
	}

	// Parse evasion technique
	var evasionType payloads.EvasionType
	if v, ok := opts.ExtraOpts["evasion"]; ok {
		et, err := parseEvasionType(v)
		if err != nil {
			result.Success = false
			result.Message = err.Error()
			return result, err
		}
		evasionType = et
	}

	// Get adversarial prompts from Augustus
	probePayloads, err := augustusprobe.GetAllPromptsForVulnTypes(vulnTypes)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get prompts: %v", err)
		return result, err
	}

	// Collect all prompts up to maxPrompts
	var allPrompts []augustusprobe.DeliveredPayload
	for _, payload := range probePayloads {
		for _, prompt := range payload.Prompts {
			if len(allPrompts) >= maxPrompts {
				break
			}
			allPrompts = append(allPrompts, augustusprobe.DeliveredPayload{
				ProbeName: payload.ProbeName,
				Prompt:    prompt,
			})
		}
		if len(allPrompts) >= maxPrompts {
			break
		}
	}

	if len(allPrompts) == 0 {
		result.Success = false
		result.Message = "no prompts available for delivery"
		return result, fmt.Errorf("empty prompt set")
	}

	// Apply evasion to each prompt
	for i := range allPrompts {
		allPrompts[i].Prompt = augustusprobe.ApplyEvasion(allPrompts[i].Prompt, evasionType)
	}

	// Collect probe names
	probeNames := make([]string, 0, len(probePayloads))
	for _, payload := range probePayloads {
		probeNames = append(probeNames, payload.ProbeName)
	}

	injectionResults := &augustusprobe.PromptInjectionResults{
		DeliveryMethod: string(delivery),
		TriggerType:    getTriggerFromFindings(opts.Findings),
		ProbesUsed:     probeNames,
		TotalPrompts:   len(allPrompts),
		EvasionUsed:    string(evasionType),
	}

	// Dry run: return what would be delivered
	if opts.DryRun {
		// Fill in location for dry-run reporting
		for i := range allPrompts {
			allPrompts[i].Location = locationForDelivery(delivery, i)
		}
		injectionResults.Payloads = allPrompts

		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would deliver %d adversarial prompt(s) via %s using %d probe(s)",
			len(allPrompts), delivery, len(probeNames))
		result.Data = injectionResults
		return result, nil
	}

	// Deliver based on method
	switch delivery {
	case deliveryPR:
		return p.deliverViaPR(ctx, client, owner, repo, opts.SessionID, allPrompts, injectionResults, result)
	case deliveryIssue:
		return p.deliverViaIssue(ctx, client, owner, repo, allPrompts, injectionResults, result)
	case deliveryComment:
		return p.deliverViaComment(ctx, client, owner, repo, allPrompts, injectionResults, result)
	default:
		return p.deliverViaIssue(ctx, client, owner, repo, allPrompts, injectionResults, result)
	}
}

// deliverViaPR creates a branch, file changes with adversarial content, and a PR.
func (p *Plugin) deliverViaPR(ctx context.Context, client *github.Client, owner, repo, sessionID string, prompts []augustusprobe.DeliveredPayload, injResults *augustusprobe.PromptInjectionResults, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	branchName := fmt.Sprintf("trajan-ai-test-%s", sessionID)

	// Get default branch
	defaultBranch, err := common.GetDefaultBranch(ctx, client, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get default branch: %v", err)
		return result, err
	}

	// Get branch SHA
	branchSHA, err := common.GetBranchSHA(ctx, client, owner, repo, defaultBranch)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get branch SHA: %v", err)
		return result, err
	}

	// Create attack branch
	_, err = client.CreateBranch(ctx, owner, repo, branchName, branchSHA)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create branch: %v", err)
		return result, err
	}

	// Register branch cleanup immediately so it's cleaned up on partial failure
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Description: "Branch for AI prompt injection test",
	})
	result.CleanupActions = append(result.CleanupActions, attacks.CleanupAction{
		Type:        attacks.ArtifactBranch,
		Identifier:  branchName,
		Action:      "delete",
		Description: "Delete AI injection test branch",
	})

	// Collect all prompt strings for file content formatters
	var promptStrings []string
	for _, pr := range prompts {
		promptStrings = append(promptStrings, pr.Prompt)
	}

	// File 1: Python config with prompts in code comments (primary injection surface)
	pyContent := augustusprobe.FormatForCodeComment(promptStrings)
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, "config/settings.py", github.FileContentInput{
		Message: augustusprobe.FormatForCommitMessage(prompts[0].Prompt),
		Content: common.EncodeBase64(pyContent),
		Branch:  branchName,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create Python config file: %v", err)
		return result, err
	}

	// Mark prompts used in code comments
	prompts[0].Location = "file_diff"
	for i := 1; i < len(prompts); i++ {
		prompts[i].Location = "file_diff"
	}

	// File 2: Markdown with HTML-hidden prompts
	mdContent := augustusprobe.FormatForMarkdownHidden(promptStrings)
	_, err = client.CreateOrUpdateFile(ctx, owner, repo, "docs/configuration.md", github.FileContentInput{
		Message: "docs: update configuration documentation",
		Content: common.EncodeBase64(mdContent),
		Branch:  branchName,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create markdown file: %v", err)
		return result, err
	}

	// PR title and body still carry prompts (secondary surface)
	prTitle := augustusprobe.FormatForPRTitle(prompts[0].Prompt)

	var bodyPromptStrings []string
	for i := 1; i < len(prompts); i++ {
		bodyPromptStrings = append(bodyPromptStrings, prompts[i].Prompt)
	}
	prBody := augustusprobe.FormatForPRBody(bodyPromptStrings)

	pr, err := client.CreatePullRequest(ctx, owner, repo, github.PullRequestInput{
		Title: prTitle,
		Body:  prBody,
		Head:  branchName,
		Base:  defaultBranch,
	})
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create PR: %v", err)
		return result, err
	}

	// Register PR cleanup incrementally
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactPR,
		Identifier:  fmt.Sprintf("%d", pr.Number),
		Description: fmt.Sprintf("PR #%d with adversarial prompts for AI testing", pr.Number),
		URL:         pr.HTMLURL,
	})
	result.CleanupActions = append(result.CleanupActions, attacks.CleanupAction{
		Type:        attacks.ArtifactPR,
		Identifier:  fmt.Sprintf("%d", pr.Number),
		Action:      "close",
		Description: "Close AI injection test PR",
	})

	injResults.Payloads = prompts
	result.Success = true
	result.Message = fmt.Sprintf("Delivered %d adversarial prompt(s) via PR #%d. Monitor AI tool responses.",
		len(prompts), pr.Number)
	result.Data = injResults

	return result, nil
}

// deliverViaIssue creates an issue with adversarial content in the title and body.
func (p *Plugin) deliverViaIssue(ctx context.Context, client *github.Client, owner, repo string, prompts []augustusprobe.DeliveredPayload, injResults *augustusprobe.PromptInjectionResults, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	issueTitle := augustusprobe.FormatForPRTitle(prompts[0].Prompt)
	prompts[0].Location = "issue_title"

	var bodyPromptStrings []string
	for i := 1; i < len(prompts); i++ {
		bodyPromptStrings = append(bodyPromptStrings, prompts[i].Prompt)
		prompts[i].Location = "issue_body"
	}
	issueBody := augustusprobe.FormatForIssueBody(bodyPromptStrings)

	issue, err := client.CreateIssue(ctx, owner, repo, issueTitle, issueBody)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create issue: %v", err)
		return result, err
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactIssue,
		Identifier:  fmt.Sprintf("%d", issue.Number),
		Description: fmt.Sprintf("Issue #%d with adversarial prompts for AI testing", issue.Number),
		URL:         issue.HTMLURL,
	})

	injResults.Payloads = prompts
	result.Success = true
	result.Message = fmt.Sprintf("Delivered %d adversarial prompt(s) via issue #%d. Monitor AI tool responses.",
		len(prompts), issue.Number)
	result.Data = injResults
	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        attacks.ArtifactIssue,
			Identifier:  fmt.Sprintf("%d", issue.Number),
			Action:      "close",
			Description: "Close AI injection test issue",
		},
	}

	return result, nil
}

// deliverViaComment creates an issue and adds adversarial content as a comment.
func (p *Plugin) deliverViaComment(ctx context.Context, client *github.Client, owner, repo string, prompts []augustusprobe.DeliveredPayload, injResults *augustusprobe.PromptInjectionResults, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	// Create a benign issue first
	issue, err := client.CreateIssue(ctx, owner, repo,
		"AI security test - Trajan",
		"This issue was created by Trajan for AI security testing. It can be safely closed.")
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create issue: %v", err)
		return result, err
	}

	// Register issue cleanup immediately so it's cleaned up on partial failure
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactIssue,
		Identifier:  fmt.Sprintf("%d", issue.Number),
		Description: fmt.Sprintf("Issue #%d for comment-based AI injection test", issue.Number),
		URL:         issue.HTMLURL,
	})
	result.CleanupActions = append(result.CleanupActions, attacks.CleanupAction{
		Type:        attacks.ArtifactIssue,
		Identifier:  fmt.Sprintf("%d", issue.Number),
		Action:      "close",
		Description: "Close AI injection test issue",
	})

	// Add adversarial content as comment
	var promptStrings []string
	for i := range prompts {
		promptStrings = append(promptStrings, prompts[i].Prompt)
		prompts[i].Location = "issue_comment"
	}
	commentBody := augustusprobe.FormatForIssueComment(promptStrings)

	comment, err := client.CreateIssueComment(ctx, owner, repo, issue.Number, commentBody)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create comment: %v", err)
		return result, err
	}

	// Register comment cleanup incrementally
	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactComment,
		Identifier:  fmt.Sprintf("%d", comment.ID),
		Description: "Comment with adversarial prompts",
		URL:         comment.HTMLURL,
	})
	result.CleanupActions = append(result.CleanupActions, attacks.CleanupAction{
		Type:        attacks.ArtifactComment,
		Identifier:  fmt.Sprintf("%d", comment.ID),
		Action:      "delete",
		Description: "Delete AI injection test comment",
	})

	injResults.Payloads = prompts
	result.Success = true
	result.Message = fmt.Sprintf("Delivered %d adversarial prompt(s) via issue #%d comment. Monitor AI tool responses.",
		len(prompts), issue.Number)
	result.Data = injResults

	return result, nil
}

// Cleanup removes artifacts created by the attack (best-effort).
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	ghPlatform, ok := session.Platform.(*github.Platform)
	if !ok {
		return fmt.Errorf("invalid platform type")
	}

	client := ghPlatform.Client()
	var errs []error

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

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
				var prNum int
				if _, err := fmt.Sscanf(action.Identifier, "%d", &prNum); err != nil {
					fmt.Fprintf(os.Stderr, "  Invalid PR number %s: %v\n", action.Identifier, err)
					continue
				}
				if err := client.ClosePullRequest(ctx, owner, repo, prNum); err != nil {
					errs = append(errs, fmt.Errorf("closing PR %d: %w", prNum, err))
					continue
				}
			case attacks.ArtifactBranch:
				if err := client.DeleteBranch(ctx, owner, repo, action.Identifier); err != nil {
					errs = append(errs, fmt.Errorf("deleting branch %s: %w", action.Identifier, err))
					continue
				}
			case attacks.ArtifactIssue:
				var issueNum int
				if _, err := fmt.Sscanf(action.Identifier, "%d", &issueNum); err != nil {
					fmt.Fprintf(os.Stderr, "  Invalid issue number %s: %v\n", action.Identifier, err)
					continue
				}
				if err := client.CloseIssue(ctx, owner, repo, issueNum); err != nil {
					errs = append(errs, fmt.Errorf("closing issue %d: %w", issueNum, err))
					continue
				}
			case attacks.ArtifactComment:
				var commentID int
				if _, err := fmt.Sscanf(action.Identifier, "%d", &commentID); err != nil {
					fmt.Fprintf(os.Stderr, "  Invalid comment ID %s: %v\n", action.Identifier, err)
					continue
				}
				if err := client.DeleteIssueComment(ctx, owner, repo, commentID); err != nil {
					errs = append(errs, fmt.Errorf("deleting comment %d: %w", commentID, err))
					continue
				}
			}
		}
	}

	return errors.Join(errs...)
}

// analyzeFindings determines the best delivery method and which AI vuln types are present.
func analyzeFindings(findings []detections.Finding) (deliveryMethod, []detections.VulnerabilityType) {
	var foundVulnTypes []detections.VulnerabilityType
	seen := make(map[detections.VulnerabilityType]bool)

	bestDelivery := deliveryIssue // default
	hasPR := false
	hasComment := false
	hasIssue := false

	for _, f := range findings {
		// Collect AI vuln types
		for _, vt := range aiVulnTypes {
			if f.Type == vt && !seen[vt] {
				seen[vt] = true
				foundVulnTypes = append(foundVulnTypes, vt)
			}
		}

		// Determine delivery from trigger
		trigger := strings.ToLower(f.Trigger)
		switch {
		case strings.Contains(trigger, "issue_comment"):
			hasComment = true
		case strings.Contains(trigger, "issues"):
			hasIssue = true
		case strings.Contains(trigger, "pull_request"):
			hasPR = true
		}
	}

	// Prefer PR > issue > comment (PRs trigger AI code review, which is the primary target)
	if hasPR {
		bestDelivery = deliveryPR
	} else if hasIssue {
		bestDelivery = deliveryIssue
	} else if hasComment {
		bestDelivery = deliveryComment
	}

	// Default to CodeInjection if no specific AI types found
	if len(foundVulnTypes) == 0 {
		foundVulnTypes = []detections.VulnerabilityType{detections.VulnAICodeInjection}
	}

	return bestDelivery, foundVulnTypes
}

// getTriggerFromFindings extracts the first trigger string from AI findings.
func getTriggerFromFindings(findings []detections.Finding) string {
	for _, f := range findings {
		for _, vt := range aiVulnTypes {
			if f.Type == vt && f.Trigger != "" {
				return f.Trigger
			}
		}
	}
	return ""
}

// parseDeliveryOverride converts user-facing strings to delivery methods.
func parseDeliveryOverride(s string) (deliveryMethod, error) {
	switch strings.ToLower(s) {
	case "pr", "pull_request":
		return deliveryPR, nil
	case "issue", "issues":
		return deliveryIssue, nil
	case "comment", "issue_comment":
		return deliveryComment, nil
	default:
		return "", fmt.Errorf("invalid delivery method %q: must be one of pr, pull_request, issue, issues, comment, issue_comment", s)
	}
}

// validEvasionTypes is the set of recognized evasion technique names.
var validEvasionTypes = map[payloads.EvasionType]bool{
	payloads.EvasionNone:          true,
	payloads.EvasionHomoglyph:     true,
	payloads.EvasionZeroWidth:     true,
	payloads.EvasionEmojiSmuggle:  true,
	payloads.EvasionCaseSwap:      true,
	payloads.EvasionUnicodeEscape: true,
	payloads.EvasionBase64:        true,
}

// parseEvasionType validates and returns an evasion type from a user string.
func parseEvasionType(s string) (payloads.EvasionType, error) {
	et := payloads.EvasionType(s)
	if !validEvasionTypes[et] {
		return "", fmt.Errorf("invalid evasion type %q: must be one of homoglyph, zero_width, emoji_smuggle, case_swap, unicode_escape, base64", s)
	}
	return et, nil
}

// locationForDelivery returns the location string for a prompt based on delivery method and index.
func locationForDelivery(dm deliveryMethod, index int) string {
	switch dm {
	case deliveryPR:
		// PR delivery now embeds prompts in file diffs as primary surface
		return "file_diff"
	case deliveryIssue:
		if index == 0 {
			return "issue_title"
		}
		return "issue_body"
	case deliveryComment:
		return "issue_comment"
	default:
		return "unknown"
	}
}
