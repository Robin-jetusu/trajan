package common

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/detections/aipatterns"
	"github.com/praetorian-inc/trajan/pkg/detections/shared/taintsources"
)

// AIActionPatterns detect AI/LLM actions by name (30+ providers)
var AIActionPatterns = aipatterns.AIActionPatterns

// IsAIAction checks if step uses AI/LLM action
func IsAIAction(uses string) bool {
	return aipatterns.IsAIAction(uses)
}

// UntrustedInputContexts are external user-controlled contexts
var UntrustedInputContexts = taintsources.GitHubTaintedContexts

// ContainsUntrustedInput checks for untrusted GitHub contexts
func ContainsUntrustedInput(s string) bool {
	for _, ctx := range UntrustedInputContexts {
		if strings.Contains(s, ctx) {
			return true
		}
	}
	return false
}

// AITriggers allow external user interaction
var AITriggers = []string{
	"issue_comment",
	"pull_request_review_comment",
	"discussion_comment",
	"issues",
	"pull_request_target",
	"workflow_run",
}

// IsAITrigger checks if trigger allows untrusted input
func IsAITrigger(trigger string) bool {
	for _, t := range AITriggers {
		if strings.Contains(trigger, t) {
			return true
		}
	}
	return false
}
