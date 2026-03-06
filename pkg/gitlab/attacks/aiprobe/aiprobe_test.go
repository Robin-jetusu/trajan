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
	"github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestCanAttack_WithAIVulnerabilities(t *testing.T) {
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
			name:     "ai_mcp_abuse",
			findings: []detections.Finding{{Type: detections.VulnAIMCPAbuse}},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, plugin.CanAttack(tt.findings))
		})
	}
}

func TestCanAttack_NoAIVulnerabilities(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
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
			name:     "non-AI finding - merge request unsafe checkout",
			findings: []detections.Finding{{Type: detections.VulnMergeRequestUnsafeCheckout}},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, plugin.CanAttack(tt.findings))
		})
	}
}

func TestCanAttack_EmptyFindings(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
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

func TestExecute_DryRun_FetchesCIFile(t *testing.T) {
	// Mock GitLab API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v4/projects/mygroup/myproject":
			// Return project metadata
			project := map[string]interface{}{
				"id":                  123,
				"path_with_namespace": "mygroup/myproject",
				"default_branch":      "main",
			}
			json.NewEncoder(w).Encode(project)
		case r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab-ci.yml" && r.URL.Query().Get("ref") == "main":
			// Return base64-encoded CI file
			ciContent := `
test-job:
  script:
    - echo "Testing AI integration"
  variables:
    OLLAMA_HOST: http://gpu-server:11434
`
			encoded := base64.StdEncoding.EncodeToString([]byte(ciContent))
			fileResp := map[string]interface{}{
				"file_path": ".gitlab-ci.yml",
				"content":   encoded,
				"encoding":  "base64",
			}
			json.NewEncoder(w).Encode(fileResp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create GitLab platform pointing to mock server
	platform := gitlab.NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	// Execute plugin with DryRun
	plugin := New()
	opts := attacks.AttackOptions{
		Platform:  platform,
		Target:    platforms.Target{Value: "mygroup/myproject"},
		DryRun:    true,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "Discovered")
	assert.Contains(t, result.Message, "1")

	// Verify ScanResults structure
	scanResults, ok := result.Data.(*sharedaiprobe.ScanResults)
	require.True(t, ok, "result.Data should be *sharedaiprobe.ScanResults")
	assert.NotEmpty(t, scanResults.Endpoints)
}

func TestExecute_ActiveProbing(t *testing.T) {
	// Mock GitLab API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v4/projects/mygroup/myproject":
			// Return project metadata
			project := map[string]interface{}{
				"id":                  123,
				"path_with_namespace": "mygroup/myproject",
				"default_branch":      "main",
			}
			json.NewEncoder(w).Encode(project)
		case r.URL.Path == "/api/v4/projects/123/repository/files/.gitlab-ci.yml" && r.URL.Query().Get("ref") == "main":
			// Return base64-encoded CI file with 2 AI endpoints
			ciContent := `
test-job:
  script:
    - echo "Testing AI integration"
  variables:
    OLLAMA_HOST: http://gpu-server:11434
    OPENAI_API_BASE: https://api.openai.com/v1
`
			encoded := base64.StdEncoding.EncodeToString([]byte(ciContent))
			fileResp := map[string]interface{}{
				"file_path": ".gitlab-ci.yml",
				"content":   encoded,
				"encoding":  "base64",
			}
			json.NewEncoder(w).Encode(fileResp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create GitLab platform pointing to mock server
	platform := gitlab.NewPlatform()
	err := platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	// Execute plugin with DryRun: false (active mode)
	plugin := New()
	opts := attacks.AttackOptions{
		Platform:  platform,
		Target:    platforms.Target{Value: "mygroup/myproject"},
		DryRun:    false,
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "Probed")
	assert.Contains(t, result.Message, "endpoint")

	// Verify ScanResults structure
	scanResults, ok := result.Data.(*sharedaiprobe.ScanResults)
	require.True(t, ok, "result.Data should be *sharedaiprobe.ScanResults")
	assert.Equal(t, 2, scanResults.Summary.EndpointsDiscovered, "Should discover 2 endpoints")
	assert.Equal(t, 2, scanResults.Summary.EndpointsProbed, "Should probe 2 endpoints")
}
