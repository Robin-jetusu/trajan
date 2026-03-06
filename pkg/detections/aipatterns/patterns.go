package aipatterns

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// AIActionPatterns detect AI/LLM actions by name (30+ providers)
var AIActionPatterns = []string{
	// Major providers
	"claude", "gemini", "copilot", "openai", "codex",
	// AI assistants
	"cursor", "coderabbit", "qodo", "pr-agent", "devin",
	"sourcery", "ai-pr-review", "ai-code-review", "cline",
	// Additional LLM providers
	"mistral", "llama", "anthropic", "cohere",
	"chatgpt", "gpt-4", "gpt-3", "bing-chat", "bard",
	"phind", "perplexity", "you-ai", "jasper", "tabnine",
	// Self-hosted LLM runtimes
	"ollama",
	// MCP-enabled
	"mcp", "model-context-protocol",
}

// AIEnvKeyPatterns detect AI/LLM usage via environment variable names.
// Matched case-insensitively against env key names at step, job, and workflow levels.
var AIEnvKeyPatterns = []string{
	"openai_api_key", "openai_api_token",
	"anthropic_api_key",
	"claude_api_key",
	"cohere_api_key",
	"mistral_api_key",
	"huggingface_token", "hf_token",
	"ollama_host", "ollama_base_url",
	"groq_api_key",
}

// IsAIAction checks if a string (action ref, pipe name, task ref, or script) references an AI tool
func IsAIAction(s string) bool {
	lower := strings.ToLower(s)
	for _, pattern := range AIActionPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// HasAIEnvVars checks if a step's environment variables reference AI/LLM services.
func HasAIEnvVars(step *graph.StepNode) bool {
	for key := range step.Env {
		keyLower := strings.ToLower(key)
		for _, pattern := range AIEnvKeyPatterns {
			if strings.Contains(keyLower, pattern) {
				return true
			}
		}
	}
	return false
}

// IsAIStep checks if a step references an AI tool via its Uses, Run, or Env fields.
func IsAIStep(step *graph.StepNode) bool {
	return IsAIAction(step.Uses) || IsAIAction(step.Run) || HasAIEnvVars(step)
}

// CheckMCPIndicators checks if a step has MCP configuration in its Env or With maps.
func CheckMCPIndicators(step *graph.StepNode) bool {
	if step.Env != nil {
		for key, value := range step.Env {
			keyUpper := strings.ToUpper(key)
			valueLower := strings.ToLower(value)
			if strings.Contains(keyUpper, "MCP") {
				return true
			}
			if strings.Contains(valueLower, "mcp") {
				return true
			}
		}
	}
	if step.With != nil {
		for key, value := range step.With {
			keyLower := strings.ToLower(key)
			valueLower := strings.ToLower(value)
			if strings.Contains(keyLower, "mcp") {
				return true
			}
			if strings.Contains(valueLower, "mcp") {
				return true
			}
		}
	}
	return false
}

// GetTriggerString formats workflow triggers as a comma-separated string.
func GetTriggerString(wf *graph.WorkflowNode) string {
	if len(wf.Triggers) == 0 {
		return "unknown"
	}
	return strings.Join(wf.Triggers, ", ")
}
