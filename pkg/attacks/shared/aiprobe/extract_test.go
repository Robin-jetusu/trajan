package aiprobe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractEndpoints_KnownAIEnvVars(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		envVal  string
		wantURL string
	}{
		{"OPENAI_BASE_URL", "OPENAI_BASE_URL", "https://my-openai.example.com", "https://my-openai.example.com"},
		{"OLLAMA_HOST", "OLLAMA_HOST", "http://localhost:11434", "http://localhost:11434"},
		{"ANTHROPIC_BASE_URL", "ANTHROPIC_BASE_URL", "https://anthropic.internal:8443", "https://anthropic.internal:8443"},
		{"AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_ENDPOINT", "https://my-azure.openai.azure.com/", "https://my-azure.openai.azure.com"},
		{"VLLM_API_BASE", "VLLM_API_BASE", "http://gpu-server:8000", "http://gpu-server:8000"},
		{"LITELLM_BASE_URL", "LITELLM_BASE_URL", "http://litellm-proxy:4000", "http://litellm-proxy:4000"},
		{"HF_INFERENCE_ENDPOINT", "HF_INFERENCE_ENDPOINT", "https://hf-endpoint.example.com", "https://hf-endpoint.example.com"},
		{"LLM_BASE_URL", "LLM_BASE_URL", "https://llm.internal.io", "https://llm.internal.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := []byte("env:\n  " + tt.envVar + ": " + tt.envVal + "\n")
			endpoints := ExtractEndpoints(yaml, "workflow.yml")

			require.NotEmpty(t, endpoints, "should extract endpoint for %s", tt.envVar)
			assert.Equal(t, tt.wantURL, endpoints[0].URL)
			assert.Equal(t, "high", endpoints[0].Confidence)
			assert.Equal(t, "env:"+tt.envVar, endpoints[0].Source)
			assert.Equal(t, "workflow.yml", endpoints[0].Workflow)
		})
	}
}

func TestExtractEndpoints_AIServicePorts(t *testing.T) {
	yaml := []byte(`env:
  MY_SERVICE_URL: http://internal-host:11434
  ANOTHER_URL: http://gpu-box:8000
`)
	endpoints := ExtractEndpoints(yaml, "ci.yml")

	require.Len(t, endpoints, 2)
	for _, ep := range endpoints {
		assert.Equal(t, "medium", ep.Confidence, "AI port should give medium confidence")
	}
}

func TestExtractEndpoints_RawContentAIPathSegments(t *testing.T) {
	yaml := []byte(`jobs:
  test:
    steps:
      - run: |
          curl http://ai-server.internal:9090/v1/chat/completions -d '{"model":"gpt-4"}'
`)
	endpoints := ExtractEndpoints(yaml, "deploy.yml")

	require.NotEmpty(t, endpoints)
	found := false
	for _, ep := range endpoints {
		if ep.URL == "http://ai-server.internal:9090/v1/chat/completions" {
			found = true
			assert.Equal(t, "low", ep.Confidence)
			assert.Equal(t, "script", ep.Source)
		}
	}
	assert.True(t, found, "should find URL with /v1/chat path segment")
}

func TestExtractEndpoints_WithBlock(t *testing.T) {
	yaml := []byte(`jobs:
  test:
    steps:
      - uses: some/action@v1
        with:
          api_url: http://my-llm:11434
`)
	endpoints := ExtractEndpoints(yaml, "test.yml")

	require.NotEmpty(t, endpoints)
	found := false
	for _, ep := range endpoints {
		if ep.URL == "http://my-llm:11434" {
			found = true
			assert.Equal(t, "medium", ep.Confidence)
			assert.Contains(t, ep.Source, "with:")
		}
	}
	assert.True(t, found, "should find URL from with block")
}

func TestExtractEndpoints_ADOVariablesBlock(t *testing.T) {
	yaml := []byte(`variables:
  OPENAI_BASE_URL: https://my-openai-proxy.internal
  BUILD_NUMBER: '42'
steps:
  - script: echo hello
`)
	endpoints := ExtractEndpoints(yaml, "azure-pipelines.yml")

	require.Len(t, endpoints, 1)
	assert.Equal(t, "https://my-openai-proxy.internal", endpoints[0].URL)
	assert.Equal(t, "high", endpoints[0].Confidence)
	assert.Equal(t, "variables:OPENAI_BASE_URL", endpoints[0].Source)
}

func TestExtractEndpoints_SkipsTemplateVariables(t *testing.T) {
	yaml := []byte(`env:
  OPENAI_BASE_URL: ${{ vars.OPENAI_URL }}
  OLLAMA_HOST: $(ollamaHost)
`)
	endpoints := ExtractEndpoints(yaml, "workflow.yml")
	assert.Empty(t, endpoints, "template variables should be skipped")
}

func TestExtractEndpoints_FiltersCommonURLs(t *testing.T) {
	yaml := []byte(`env:
  REPO_URL: https://github.com/owner/repo
  DOCKER_REG: https://docker.io/myimage
  NPM_REG: https://registry.npmjs.org
  OPENAI_BASE_URL: https://my-openai.example.com
`)
	endpoints := ExtractEndpoints(yaml, "workflow.yml")

	require.Len(t, endpoints, 1)
	assert.Equal(t, "https://my-openai.example.com", endpoints[0].URL)
}

func TestDeduplicateEndpoints_SameURLDifferentConfidence(t *testing.T) {
	endpoints := []DiscoveredEndpoint{
		{URL: "http://localhost:11434", Confidence: "low", Source: "script"},
		{URL: "http://localhost:11434", Confidence: "high", Source: "env:OLLAMA_HOST"},
	}

	deduped := DeduplicateEndpoints(endpoints)
	require.Len(t, deduped, 1)
	assert.Equal(t, "high", deduped[0].Confidence, "should keep highest confidence")
	assert.Equal(t, "env:OLLAMA_HOST", deduped[0].Source)
}

func TestDeduplicateEndpoints_DifferentURLs(t *testing.T) {
	endpoints := []DiscoveredEndpoint{
		{URL: "http://host-a:11434", Confidence: "high"},
		{URL: "http://host-b:8000", Confidence: "medium"},
	}

	deduped := DeduplicateEndpoints(endpoints)
	assert.Len(t, deduped, 2)
}

func TestExtractEndpoints_MalformedYAML(t *testing.T) {
	yaml := []byte(`this is: [not: {valid yaml: "`)
	// Should not panic; may return nil or empty
	assert.NotPanics(t, func() {
		ExtractEndpoints(yaml, "bad.yml")
	})
}

func TestExtractEndpoints_EmptyYAML(t *testing.T) {
	endpoints := ExtractEndpoints([]byte(""), "empty.yml")
	assert.Empty(t, endpoints)
}

func TestExtractEndpoints_MultipleStrategies(t *testing.T) {
	// URL appears in both env block AND raw content — should deduplicate
	yaml := []byte(`env:
  OLLAMA_HOST: http://localhost:11434
jobs:
  test:
    steps:
      - run: curl http://localhost:11434/api/tags
`)
	endpoints := ExtractEndpoints(yaml, "workflow.yml")

	// Count unique URLs
	urls := make(map[string]bool)
	for _, ep := range endpoints {
		urls[ep.URL] = true
	}
	// The /api/tags URL is a separate path from the base URL
	assert.LessOrEqual(t, len(endpoints), 2, "deduplication should combine same URLs")
}

func TestExtractEndpoints_NestedEnvBlocks(t *testing.T) {
	yaml := []byte(`jobs:
  build:
    runs-on: ubuntu-latest
    env:
      OPENAI_API_BASE: https://nested-openai.example.com
    steps:
      - run: echo test
`)
	endpoints := ExtractEndpoints(yaml, "nested.yml")

	require.NotEmpty(t, endpoints)
	found := false
	for _, ep := range endpoints {
		if ep.URL == "https://nested-openai.example.com" {
			found = true
			assert.Equal(t, "high", ep.Confidence)
		}
	}
	assert.True(t, found, "should find env vars in nested job blocks")
}
