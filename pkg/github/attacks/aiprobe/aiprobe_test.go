package aiprobe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	sharedaiprobe "github.com/praetorian-inc/trajan/pkg/attacks/shared/aiprobe"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestAIProbe_Properties(t *testing.T) {
	plugin := New()

	assert.Equal(t, "ai-probe", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryRecon, plugin.Category())
}

func TestAIProbe_CanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
		{
			name:     "ai_token_exfiltration",
			findings: []detections.Finding{{Type: detections.VulnAITokenExfiltration}},
			want:     true,
		},
		{
			name:     "ai_code_injection",
			findings: []detections.Finding{{Type: detections.VulnAICodeInjection}},
			want:     true,
		},
		{
			name:     "ai_workflow_sabotage",
			findings: []detections.Finding{{Type: detections.VulnAIWorkflowSabotage}},
			want:     true,
		},
		{
			name:     "ai_mcp_abuse",
			findings: []detections.Finding{{Type: detections.VulnAIMCPAbuse}},
			want:     true,
		},
		{
			name:     "ai_privilege_escalation",
			findings: []detections.Finding{{Type: detections.VulnAIPrivilegeEscalation}},
			want:     true,
		},
		{
			name:     "ai_supply_chain_poisoning",
			findings: []detections.Finding{{Type: detections.VulnAISupplyChainPoisoning}},
			want:     true,
		},
		{
			name:     "non-AI finding - actions injection",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			want:     false,
		},
		{
			name:     "non-AI finding - self-hosted runner",
			findings: []detections.Finding{{Type: detections.VulnSelfHostedRunner}},
			want:     false,
		},
		{
			name:     "empty findings",
			findings: []detections.Finding{},
			want:     false,
		},
		{
			name:     "nil findings",
			findings: nil,
			want:     false,
		},
		{
			name: "mixed AI and non-AI",
			findings: []detections.Finding{
				{Type: detections.VulnActionsInjection},
				{Type: detections.VulnAITokenExfiltration},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, plugin.CanAttack(tt.findings))
		})
	}
}

func TestAIProbe_Execute_InvalidPlatform(t *testing.T) {
	plugin := New()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  &invalidPlatform{},
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "platform is not GitHub", result.Message)
}

func TestAIProbe_Execute_NoEndpointsFound(t *testing.T) {
	plugin := New()
	// Workflow with no AI URLs
	workflowContent := base64.StdEncoding.EncodeToString([]byte(`name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "hello"
`))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/repos/owner/repo/contents/.github/workflows":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ci.yml", "path": ".github/workflows/ci.yml", "sha": "abc", "type": "file"},
			})
		case "/repos/owner/repo/contents/.github/workflows/ci.yml":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":     "ci.yml",
				"path":     ".github/workflows/ci.yml",
				"content":  workflowContent,
				"encoding": "base64",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "0 AI service endpoint(s)")

	scanResults, ok := result.Data.(*sharedaiprobe.ScanResults)
	require.True(t, ok)
	assert.Empty(t, scanResults.Endpoints)
}

func TestAIProbe_Execute_DryRun(t *testing.T) {
	plugin := New()
	// Workflow with AI endpoints
	workflowContent := base64.StdEncoding.EncodeToString([]byte(`name: AI Pipeline
on: push
jobs:
  inference:
    runs-on: ubuntu-latest
    env:
      OPENAI_BASE_URL: https://my-openai-proxy.example.com
      OLLAMA_HOST: http://gpu-server:11434
    steps:
      - run: echo "call AI"
`))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/repos/owner/repo/contents/.github/workflows":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "ai.yml", "path": ".github/workflows/ai.yml", "sha": "abc", "type": "file"},
			})
		case "/repos/owner/repo/contents/.github/workflows/ai.yml":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":     "ai.yml",
				"path":     ".github/workflows/ai.yml",
				"content":  workflowContent,
				"encoding": "base64",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "2 AI service endpoint(s)")

	scanResults, ok := result.Data.(*sharedaiprobe.ScanResults)
	require.True(t, ok)
	assert.Len(t, scanResults.Endpoints, 2)
}

func TestAIProbe_Cleanup_NoOp(t *testing.T) {
	plugin := New()
	err := plugin.Cleanup(context.Background(), &attacks.Session{})
	assert.NoError(t, err)
}

// invalidPlatform is a mock that doesn't implement *github.Platform.
type invalidPlatform struct{}

func (i *invalidPlatform) Name() string                                            { return "invalid" }
func (i *invalidPlatform) Init(ctx context.Context, config platforms.Config) error { return nil }
func (i *invalidPlatform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, nil
}
