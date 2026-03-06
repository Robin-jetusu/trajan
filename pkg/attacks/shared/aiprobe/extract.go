// Package aiprobe provides platform-agnostic AI service endpoint extraction and probing.
package aiprobe

import (
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DiscoveredEndpoint represents an AI service endpoint found in workflow YAML.
type DiscoveredEndpoint struct {
	URL        string // the actual URL to probe
	Source     string // "env:OPENAI_BASE_URL", "script", "with:api_url"
	Workflow   string // workflow file path
	Confidence string // "high", "medium", "low"
}

// knownAIEnvVars maps environment variable names to high-confidence AI service detection.
var knownAIEnvVars = map[string]bool{
	"OPENAI_BASE_URL":       true,
	"OPENAI_API_BASE":       true,
	"OPENAI_API_URL":        true,
	"ANTHROPIC_API_BASE":    true,
	"ANTHROPIC_BASE_URL":    true,
	"OLLAMA_HOST":           true,
	"OLLAMA_API_BASE":       true,
	"AZURE_OPENAI_ENDPOINT": true,
	"AZURE_OPENAI_BASE_URL": true,
	"VLLM_API_BASE":         true,
	"VLLM_URL":              true,
	"HF_INFERENCE_ENDPOINT": true,
	"LLM_BASE_URL":          true,
	"AI_API_URL":            true,
	"MODEL_API_URL":         true,
	"LLM_API_BASE":          true,
	"LITELLM_BASE_URL":      true,
	"LITELLM_API_BASE":      true,
}

// knownAIPorts maps port numbers to AI service names (medium confidence).
var knownAIPorts = map[string]string{
	"11434": "ollama",
	"8000":  "vllm",
	"4000":  "litellm",
	"8080":  "text-generation-inference",
}

// aiPathSegments identifies AI-specific URL path segments (low confidence).
var aiPathSegments = []string{
	"/v1/chat",
	"/v1/models",
	"/v1/completions",
	"/v1/embeddings",
	"/api/tags",
	"/api/generate",
	"/api/chat",
}

// excludedHosts lists common non-AI URLs to filter out.
var excludedHosts = map[string]bool{
	"github.com":                    true,
	"docker.io":                     true,
	"registry.hub.docker.com":       true,
	"npmjs.org":                     true,
	"www.npmjs.com":                 true,
	"registry.npmjs.org":            true,
	"pypi.org":                      true,
	"rubygems.org":                  true,
	"maven.apache.org":              true,
	"nuget.org":                     true,
	"api.nuget.org":                 true,
	"dev.azure.com":                 true,
	"visualstudio.com":              true,
	"gitlab.com":                    true,
	"bitbucket.org":                 true,
	"raw.githubusercontent.com":     true,
	"objects.githubusercontent.com": true,
	"api.github.com":                true,
	"ghcr.io":                       true,
	"gcr.io":                        true,
	"quay.io":                       true,
}

// templateVarPattern matches CI/CD template variables that can't be resolved statically.
var templateVarPattern = regexp.MustCompile(`\$\{\{.*?\}\}|\$\(.*?\)`)

// urlPattern matches HTTP/HTTPS URLs in text content.
var urlPattern = regexp.MustCompile(`https?://[^\s"'` + "`" + `\]\)}>]+`)

// ExtractEndpoints parses workflow YAML and extracts AI service endpoint URLs.
func ExtractEndpoints(yamlContent []byte, workflowPath string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint

	// Strategy 1: Parse YAML structure and walk env/variables/with blocks
	endpoints = append(endpoints, extractFromYAMLStructure(yamlContent, workflowPath)...)

	// Strategy 2: Regex scan raw content for URLs with AI service indicators
	endpoints = append(endpoints, extractFromRawContent(yamlContent, workflowPath)...)

	return DeduplicateEndpoints(endpoints)
}

// DeduplicateEndpoints removes duplicate URLs, keeping the highest confidence entry.
func DeduplicateEndpoints(endpoints []DiscoveredEndpoint) []DiscoveredEndpoint {
	confidenceRank := map[string]int{"high": 3, "medium": 2, "low": 1}

	seen := make(map[string]int) // URL -> index in result
	var result []DiscoveredEndpoint

	for _, ep := range endpoints {
		if idx, exists := seen[ep.URL]; exists {
			// Keep the higher confidence one
			if confidenceRank[ep.Confidence] > confidenceRank[result[idx].Confidence] {
				result[idx] = ep
			}
		} else {
			seen[ep.URL] = len(result)
			result = append(result, ep)
		}
	}

	return result
}

// extractFromYAMLStructure parses the YAML and walks known blocks for env vars.
func extractFromYAMLStructure(yamlContent []byte, workflowPath string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint

	// Parse as generic map to handle both GitHub Actions and ADO pipeline formats
	var doc map[string]interface{}
	if err := yaml.Unmarshal(yamlContent, &doc); err != nil {
		return nil
	}

	// Walk the entire document tree looking for env vars and with blocks
	walkMap(doc, workflowPath, &endpoints)

	return endpoints
}

// walkMap recursively walks a map looking for env vars, with blocks, and variables blocks.
func walkMap(m map[string]interface{}, workflowPath string, endpoints *[]DiscoveredEndpoint) {
	for key, value := range m {
		switch key {
		case "env", "variables":
			if envMap, ok := value.(map[string]interface{}); ok {
				extractFromEnvMap(envMap, key, workflowPath, endpoints)
			}
		case "with":
			if withMap, ok := value.(map[string]interface{}); ok {
				extractFromWithMap(withMap, workflowPath, endpoints)
			}
		}

		// Recurse into nested structures
		switch v := value.(type) {
		case map[string]interface{}:
			walkMap(v, workflowPath, endpoints)
		case []interface{}:
			walkSlice(v, workflowPath, endpoints)
		}
	}
}

// walkSlice recursively walks a slice looking for maps to inspect.
func walkSlice(s []interface{}, workflowPath string, endpoints *[]DiscoveredEndpoint) {
	for _, item := range s {
		if m, ok := item.(map[string]interface{}); ok {
			walkMap(m, workflowPath, endpoints)
		}
	}
}

// extractFromEnvMap extracts URLs from env/variables blocks.
func extractFromEnvMap(envMap map[string]interface{}, blockType, workflowPath string, endpoints *[]DiscoveredEndpoint) {
	for envName, envValue := range envMap {
		valStr, ok := envValue.(string)
		if !ok {
			continue
		}

		// Skip template variables
		if templateVarPattern.MatchString(valStr) {
			continue
		}

		if !isURL(valStr) {
			continue
		}

		if isExcludedURL(valStr) {
			continue
		}

		upperName := strings.ToUpper(envName)
		if knownAIEnvVars[upperName] {
			*endpoints = append(*endpoints, DiscoveredEndpoint{
				URL:        normalizeURL(valStr),
				Source:     blockType + ":" + envName,
				Workflow:   workflowPath,
				Confidence: "high",
			})
		} else if hasAIPort(valStr) {
			*endpoints = append(*endpoints, DiscoveredEndpoint{
				URL:        normalizeURL(valStr),
				Source:     blockType + ":" + envName,
				Workflow:   workflowPath,
				Confidence: "medium",
			})
		}
	}
}

// extractFromWithMap extracts URLs from action "with" parameter blocks.
func extractFromWithMap(withMap map[string]interface{}, workflowPath string, endpoints *[]DiscoveredEndpoint) {
	for paramName, paramValue := range withMap {
		valStr, ok := paramValue.(string)
		if !ok {
			continue
		}

		if templateVarPattern.MatchString(valStr) {
			continue
		}

		if !isURL(valStr) {
			continue
		}

		if isExcludedURL(valStr) {
			continue
		}

		// with blocks containing URLs with AI indicators are medium confidence
		if hasAIPort(valStr) || hasAIPathSegment(valStr) || isAIRelatedParamName(paramName) {
			*endpoints = append(*endpoints, DiscoveredEndpoint{
				URL:        normalizeURL(valStr),
				Source:     "with:" + paramName,
				Workflow:   workflowPath,
				Confidence: "medium",
			})
		}
	}
}

// extractFromRawContent scans raw YAML text for URLs with AI indicators.
func extractFromRawContent(yamlContent []byte, workflowPath string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint

	matches := urlPattern.FindAllString(string(yamlContent), -1)
	for _, rawURL := range matches {
		// Clean trailing punctuation
		rawURL = strings.TrimRight(rawURL, ".,;:!?)")

		if templateVarPattern.MatchString(rawURL) {
			continue
		}

		if isExcludedURL(rawURL) {
			continue
		}

		if hasAIPathSegment(rawURL) {
			endpoints = append(endpoints, DiscoveredEndpoint{
				URL:        normalizeURL(rawURL),
				Source:     "script",
				Workflow:   workflowPath,
				Confidence: "low",
			})
		}
	}

	return endpoints
}

// isURL checks if a string looks like an HTTP(S) URL.
func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// isExcludedURL checks if a URL belongs to a known non-AI host.
func isExcludedURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := strings.ToLower(u.Hostname())
	return excludedHosts[host]
}

// hasAIPort checks if a URL uses a known AI service port.
func hasAIPort(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	port := u.Port()
	_, ok := knownAIPorts[port]
	return ok
}

// hasAIPathSegment checks if a URL contains known AI API path segments.
func hasAIPathSegment(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, seg := range aiPathSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

// isAIRelatedParamName checks if a parameter name suggests an AI endpoint.
func isAIRelatedParamName(name string) bool {
	lower := strings.ToLower(name)
	aiKeywords := []string{"api_url", "api_base", "endpoint", "base_url", "model_url", "llm_url"}
	for _, kw := range aiKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// normalizeURL strips trailing slashes and cleans the URL.
func normalizeURL(rawURL string) string {
	return strings.TrimRight(rawURL, "/")
}
