package common

import (
	"testing"
)

// TestIsAIAction tests AI action pattern detection
func TestIsAIAction(t *testing.T) {
	tests := []struct {
		name     string
		uses     string
		expected bool
	}{
		// Positive cases - should detect AI actions
		{"gemini action", "google/gemini-action@v1", true},
		{"claude action", "anthropic/claude-action@v1", true},
		{"coderabbit", "coderabbit/github-action@v1", true},
		{"qodo action", "qodo-dev/qodo@v1", true},
		{"pr-agent", "Codium-ai/pr-agent@v1", true},
		{"copilot", "github/copilot@v1", true},
		{"cursor", "anysphere/cursor@v1", true},
		{"openai action", "openai/action@v1", true},
		{"codex", "openai/codex@v1", true},
		{"devin", "devin-action@v1", true},
		{"sourcery", "sourcery-ai/sourcery@v1", true},
		{"ai-pr-review", "some-org/ai-pr-review@v1", true},
		{"ai-code-review", "some-org/ai-code-review@v1", true},

		// New pattern positive cases
		{"mistral action", "mistralai/mistral-action@v1", true},
		{"llama action", "meta/llama-runner@v1", true},
		{"anthropic action", "anthropic/tool@v1", true},
		{"cohere action", "cohere/generate@v1", true},
		{"chatgpt action", "openai/chatgpt-review@v1", true},
		{"gpt-4 action", "some-org/gpt-4-tool@v1", true},
		{"mcp action", "org/mcp-server@v1", true},
		{"model-context-protocol", "org/model-context-protocol@v1", true},
		{"perplexity action", "perplexity/search@v1", true},
		{"bard action", "google/bard-action@v1", true},

		// Case insensitivity tests
		{"CLAUDE uppercase", "ANTHROPIC/CLAUDE@v1", true},
		{"CoDe-rAbBiT mixed case", "CodeRabbit/github-action@v1", true},
		{"GEMINI uppercase", "GOOGLE/GEMINI@v1", true},

		// Negative cases - should not detect
		{"regular github action", "actions/checkout@v3", false},
		{"setup node", "actions/setup-node@v3", false},
		{"upload artifact", "actions/upload-artifact@v3", false},
		{"custom action", "my-org/my-action@v1", false},
		{"empty string", "", false},
		{"no ai pattern", "some/random-action@v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAIAction(tt.uses)
			if result != tt.expected {
				t.Errorf("IsAIAction(%q) = %v, want %v", tt.uses, result, tt.expected)
			}
		})
	}
}

// TestContainsUntrustedInput tests untrusted input detection
func TestContainsUntrustedInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect untrusted input
		{"issue body", "github.event.issue.body", true},
		{"issue title", "github.event.issue.title", true},
		{"pr body", "github.event.pull_request.body", true},
		{"pr title", "github.event.pull_request.title", true},
		{"comment body", "github.event.comment.body", true},
		{"review body", "github.event.review.body", true},
		{"review comment", "github.event.review_comment.body", true},
		{"commit message", "github.event.commits.*.message", true},
		{"head commit", "github.event.head_commit.message", true},
		{"discussion body", "github.event.discussion.body", true},
		{"discussion title", "github.event.discussion.title", true},
		{"discussion comment body", "github.event.discussion_comment.body", true},

		// In expression context
		{"in expression", "${{ github.event.issue.body }}", true},
		{"in run command", "run: echo ${{ github.event.pull_request.body }}", true},

		// Negative cases - should not detect
		{"safe context", "github.event.repository", false},
		{"action path", "github.action_path", false},
		{"workflow ref", "github.workflow_ref", false},
		{"empty string", "", false},
		{"random input", "some random text", false},
		{"actor only", "github.actor", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsUntrustedInput(tt.input)
			if result != tt.expected {
				t.Errorf("ContainsUntrustedInput(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsAITrigger tests AI-triggerable event detection
func TestIsAITrigger(t *testing.T) {
	tests := []struct {
		name     string
		trigger  string
		expected bool
	}{
		// Positive cases - allow untrusted input
		{"issue_comment", "issue_comment", true},
		{"pull_request_review_comment", "pull_request_review_comment", true},
		{"discussion_comment", "discussion_comment", true},
		{"issues", "issues", true},
		{"pull_request_target", "pull_request_target", true},
		{"workflow_run", "workflow_run", true},

		// In full event context
		{"full trigger with comment", "on: [issue_comment]", true},
		{"full trigger with target", "on: pull_request_target", true},

		// Negative cases - don't allow untrusted input
		{"pull_request", "pull_request", false},
		{"push", "push", false},
		{"workflow_dispatch", "workflow_dispatch", false},
		{"schedule", "schedule", false},
		{"release", "release", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAITrigger(tt.trigger)
			if result != tt.expected {
				t.Errorf("IsAITrigger(%q) = %v, want %v", tt.trigger, result, tt.expected)
			}
		})
	}
}

// TestAIActionPatterns verifies all patterns are defined
func TestAIActionPatterns(t *testing.T) {
	if len(AIActionPatterns) == 0 {
		t.Error("AIActionPatterns is empty")
	}

	// Verify some expected patterns exist
	expectedPatterns := []string{"gemini", "claude", "coderabbit", "qodo", "pr-agent", "mistral", "mcp", "chatgpt"}
	patternMap := make(map[string]bool)
	for _, p := range AIActionPatterns {
		patternMap[p] = true
	}

	for _, expected := range expectedPatterns {
		if !patternMap[expected] {
			t.Errorf("Expected pattern %q not found in AIActionPatterns", expected)
		}
	}
}

// TestUntrustedInputContexts verifies all contexts are defined
func TestUntrustedInputContexts(t *testing.T) {
	if len(UntrustedInputContexts) == 0 {
		t.Error("UntrustedInputContexts is empty")
	}

	// Verify some expected contexts exist
	expectedContexts := []string{
		"github.event.issue.body",
		"github.event.pull_request.body",
		"github.event.comment.body",
	}

	contextMap := make(map[string]bool)
	for _, c := range UntrustedInputContexts {
		contextMap[c] = true
	}

	for _, expected := range expectedContexts {
		if !contextMap[expected] {
			t.Errorf("Expected context %q not found in UntrustedInputContexts", expected)
		}
	}
}

// TestAITriggers verifies all triggers are defined
func TestAITriggers(t *testing.T) {
	if len(AITriggers) == 0 {
		t.Error("AITriggers is empty")
	}

	// Verify some expected triggers exist
	expectedTriggers := []string{"issue_comment", "pull_request_target"}
	triggerMap := make(map[string]bool)
	for _, tr := range AITriggers {
		triggerMap[tr] = true
	}

	for _, expected := range expectedTriggers {
		if !triggerMap[expected] {
			t.Errorf("Expected trigger %q not found in AITriggers", expected)
		}
	}
}

// TestIsAIActionEdgeCases tests edge cases for IsAIAction
func TestIsAIActionEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		uses     string
		expected bool
	}{
		{"whitespace with pattern", "  claude  ", true},
		{"pattern in middle", "myorg/claude-wrapper@v1", true},
		{"similar but different", "claud-e/not-related@v1", false},
		{"partial match at end", "my-copilot", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAIAction(tt.uses)
			if result != tt.expected {
				t.Errorf("IsAIAction(%q) = %v, want %v", tt.uses, result, tt.expected)
			}
		})
	}
}

// TestCombinedAIDetection tests the combination of AI detection scenarios
func TestCombinedAIDetection(t *testing.T) {
	tests := []struct {
		name           string
		actionName     string
		trigger        string
		hasUntrusted   string
		shouldFlagRisk bool
	}{
		{
			name:           "AI action with untrusted trigger and context - HIGH RISK",
			actionName:     "anthropic/claude-action@v1",
			trigger:        "issue_comment",
			hasUntrusted:   "github.event.comment.body",
			shouldFlagRisk: true,
		},
		{
			name:           "AI action with safe trigger - NO RISK",
			actionName:     "anthropic/claude-action@v1",
			trigger:        "push",
			hasUntrusted:   "",
			shouldFlagRisk: false,
		},
		{
			name:           "Non-AI action with untrusted context - NO RISK",
			actionName:     "actions/checkout@v3",
			trigger:        "issue_comment",
			hasUntrusted:   "github.event.comment.body",
			shouldFlagRisk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasAI := IsAIAction(tt.actionName)
			hasUnsafeTrigger := IsAITrigger(tt.trigger)
			hasUntrustedCtx := ContainsUntrustedInput(tt.hasUntrusted)

			risk := hasAI && hasUnsafeTrigger && hasUntrustedCtx

			if risk != tt.shouldFlagRisk {
				t.Errorf("Combined detection failed: AI=%v, Trigger=%v, Context=%v, Risk=%v, want %v",
					hasAI, hasUnsafeTrigger, hasUntrustedCtx, risk, tt.shouldFlagRisk)
			}
		})
	}
}
