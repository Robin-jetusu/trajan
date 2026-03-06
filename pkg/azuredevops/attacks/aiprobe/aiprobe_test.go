package aiprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	sharedaiprobe "github.com/praetorian-inc/trajan/pkg/attacks/shared/aiprobe"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestADOAIProbe_Properties(t *testing.T) {
	plugin := New()

	assert.Equal(t, "ado-ai-probe", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryRecon, plugin.Category())
}

func TestADOAIProbe_CanAttack(t *testing.T) {
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
			name:     "non-AI finding - excessive permissions",
			findings: []detections.Finding{{Type: detections.VulnExcessivePermissions}},
			want:     false,
		},
		{
			name:     "non-AI finding - actions injection",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, plugin.CanAttack(tt.findings))
		})
	}
}

func TestADOAIProbe_Execute_InvalidPlatform(t *testing.T) {
	plugin := New()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "project/repo"},
		Platform:  &invalidPlatform{},
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestADOAIProbe_Execute_NoEndpointsFound(t *testing.T) {
	plugin := New()
	server := newADOMockServer(t, `trigger: none
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo "no AI here"
`)
	defer server.Close()

	platform := newADOPlatform(t, server.URL)

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "MyProject/MyRepo"},
		Platform:  platform,
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "0 AI service endpoint(s)")
}

func TestADOAIProbe_Execute_DryRun(t *testing.T) {
	server := newADOMockServer(t, `trigger: none
variables:
  OPENAI_BASE_URL: https://my-openai-proxy.internal
  OLLAMA_HOST: http://gpu-server:11434
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo "call AI"
`)
	defer server.Close()

	plugin := New()
	platform := newADOPlatform(t, server.URL)

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "MyProject/MyRepo"},
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

func TestADOAIProbe_Execute_DryRun_WithBuildDefs(t *testing.T) {
	pipelineYAML := `trigger: none
variables:
  OLLAMA_HOST: http://gpu-server:11434
pool:
  vmImage: 'ubuntu-latest'
steps:
  - script: echo "ollama call"
`
	server := newADOMockServerWithDefs(t, map[string]string{
		".azure-pipelines/ollama-review.yml": pipelineYAML,
	})
	defer server.Close()

	plugin := New()
	platform := newADOPlatform(t, server.URL)

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "MyProject/MyRepo"},
		Platform:  platform,
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "1 AI service endpoint(s)")

	scanResults, ok := result.Data.(*sharedaiprobe.ScanResults)
	require.True(t, ok)
	assert.Len(t, scanResults.Endpoints, 1)
	assert.Equal(t, "http://gpu-server:11434", scanResults.Endpoints[0].URL)
	assert.Equal(t, ".azure-pipelines/ollama-review.yml", scanResults.Endpoints[0].Workflow)
}

func TestADOAIProbe_Cleanup_NoOp(t *testing.T) {
	plugin := New()
	err := plugin.Cleanup(context.Background(), &attacks.Session{})
	assert.NoError(t, err)
}

// Test helpers

type invalidPlatform struct{}

func (i *invalidPlatform) Name() string                                            { return "invalid" }
func (i *invalidPlatform) Init(ctx context.Context, config platforms.Config) error { return nil }
func (i *invalidPlatform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, nil
}

// newADOMockServer creates a mock ADO server that returns the given pipeline YAML.
// It handles build definition listing (returns empty to trigger fallback to knownPipelinePaths).
func newADOMockServer(t *testing.T, pipelineYAML string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		// ListBuildDefinitionsByRepo — return empty to fall back to knownPipelinePaths
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/_apis/build/definitions"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}, "count": 0})

		// Repository info
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/_apis/git/repositories/"):
			if strings.Contains(r.URL.Path, "/items") {
				// GetWorkflowFile - return raw pipeline YAML
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(pipelineYAML))
				return
			}
			// GetRepository
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(azuredevops.Repository{
				ID:            "repo-id-123",
				Name:          "MyRepo",
				DefaultBranch: "refs/heads/main",
				Project:       azuredevops.Project{Name: "MyProject"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// newADOMockServerWithDefs creates a mock ADO server that returns build definitions
// pointing to specific pipeline YAML paths, then serves the YAML content for each.
func newADOMockServerWithDefs(t *testing.T, pipelines map[string]string) *httptest.Server {
	t.Helper()

	// Build definition list and detail responses
	type defEntry struct {
		id       int
		yamlPath string
		content  string
	}
	var defs []defEntry
	i := 1
	for path, content := range pipelines {
		defs = append(defs, defEntry{id: i, yamlPath: path, content: content})
		i++
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		// ListBuildDefinitionsByRepo
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/_apis/build/definitions") && r.URL.Query().Get("repositoryId") != "":
			var items []map[string]interface{}
			for _, d := range defs {
				items = append(items, map[string]interface{}{"id": d.id, "name": fmt.Sprintf("def-%d", d.id)})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"value": items, "count": len(items)})

		// GetBuildDefinition by ID
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/_apis/build/definitions/"):
			for _, d := range defs {
				if strings.HasSuffix(r.URL.Path, fmt.Sprintf("/definitions/%d", d.id)) {
					json.NewEncoder(w).Encode(map[string]interface{}{
						"id":   d.id,
						"name": fmt.Sprintf("def-%d", d.id),
						"process": map[string]interface{}{
							"yamlFilename": d.yamlPath,
							"type":         2,
						},
						"repository": map[string]interface{}{
							"id":   "repo-id-123",
							"name": "MyRepo",
							"type": "TfsGit",
						},
					})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)

		// GetRepository
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/_apis/git/repositories/"):
			if strings.Contains(r.URL.Path, "/items") {
				// GetWorkflowFile — match on path query param (has leading /)
				requestedPath := r.URL.Query().Get("path")
				requestedPath = strings.TrimPrefix(requestedPath, "/")
				for _, d := range defs {
					if requestedPath == d.yamlPath {
						w.Header().Set("Content-Type", "text/plain")
						w.Write([]byte(d.content))
						return
					}
				}
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(azuredevops.Repository{
				ID:            "repo-id-123",
				Name:          "MyRepo",
				DefaultBranch: "refs/heads/main",
				Project:       azuredevops.Project{Name: "MyProject"},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newADOPlatform(t *testing.T, baseURL string) *azuredevops.Platform {
	t.Helper()
	platform := azuredevops.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-pat",
		BaseURL: baseURL,
	}))
	return platform
}
