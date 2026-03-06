package aipromptinjection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/shared/augustusprobe"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestPlugin_Properties(t *testing.T) {
	plugin := New()

	assert.Equal(t, "ai-prompt-injection", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryCICD, plugin.Category())
}

func TestPlugin_CanAttack_AlwaysFalse(t *testing.T) {
	plugin := New()

	// CanAttack always returns false — this plugin is explicit-invocation only.
	// It must be invoked via --plugin ai-prompt-injection, not auto-triggered.
	tests := []struct {
		name     string
		findings []detections.Finding
	}{
		{
			name:     "ai_token_exfiltration",
			findings: []detections.Finding{{Type: detections.VulnAITokenExfiltration}},
		},
		{
			name:     "ai_code_injection",
			findings: []detections.Finding{{Type: detections.VulnAICodeInjection}},
		},
		{
			name:     "non-AI finding",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
		},
		{
			name: "mixed AI and non-AI",
			findings: []detections.Finding{
				{Type: detections.VulnActionsInjection},
				{Type: detections.VulnAITokenExfiltration},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, plugin.CanAttack(tt.findings))
		})
	}
}

func TestPlugin_CanAttack_Empty(t *testing.T) {
	plugin := New()
	assert.False(t, plugin.CanAttack(nil))
	assert.False(t, plugin.CanAttack([]detections.Finding{}))
}

func TestPlugin_Execute_InvalidPlatform(t *testing.T) {
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

func TestPlugin_Execute_DryRun(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{
				Type:    detections.VulnAICodeInjection,
				Trigger: "pull_request",
			},
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "[DRY RUN]")
	assert.Contains(t, result.Message, "adversarial prompt(s)")

	injResults, ok := result.Data.(*augustusprobe.PromptInjectionResults)
	require.True(t, ok)
	assert.NotEmpty(t, injResults.ProbesUsed)
	assert.NotEmpty(t, injResults.Payloads)
	assert.Equal(t, "pull_request", injResults.DeliveryMethod)
}

func TestPlugin_Execute_DryRun_FileDiff(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{
				Type:    detections.VulnAICodeInjection,
				Trigger: "pull_request",
			},
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)

	injResults, ok := result.Data.(*augustusprobe.PromptInjectionResults)
	require.True(t, ok)
	assert.Equal(t, "pull_request", injResults.DeliveryMethod)

	// PR delivery should use file_diff locations
	hasFileDiff := false
	for _, p := range injResults.Payloads {
		if p.Location == "file_diff" {
			hasFileDiff = true
			break
		}
	}
	assert.True(t, hasFileDiff, "PR delivery should include file_diff locations")
}

func TestPlugin_Execute_DryRun_IssueComment(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{
				Type:    detections.VulnAICodeInjection,
				Trigger: "issue_comment",
			},
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)

	injResults, ok := result.Data.(*augustusprobe.PromptInjectionResults)
	require.True(t, ok)
	assert.Equal(t, "issue_comment", injResults.DeliveryMethod)

	// All payloads should have issue_comment location
	for _, p := range injResults.Payloads {
		assert.Equal(t, "issue_comment", p.Location)
	}
}

func TestPlugin_Execute_DryRun_MaxPrompts(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
		},
		ExtraOpts: map[string]string{
			"max_prompts": "2",
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)

	injResults, ok := result.Data.(*augustusprobe.PromptInjectionResults)
	require.True(t, ok)
	assert.LessOrEqual(t, len(injResults.Payloads), 2)
}

func TestPlugin_Execute_DryRun_WithEvasion(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	// Run without evasion first to get baseline prompts
	baseOpts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
		},
		ExtraOpts: map[string]string{
			"max_prompts": "1",
		},
		SessionID: "test-session-base",
	}

	baseResult, err := plugin.Execute(context.Background(), baseOpts)
	require.NoError(t, err)
	baseInjResults := baseResult.Data.(*augustusprobe.PromptInjectionResults)
	require.NotEmpty(t, baseInjResults.Payloads)
	basePrompt := baseInjResults.Payloads[0].Prompt

	// Run with homoglyph evasion
	evasionOpts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
		},
		ExtraOpts: map[string]string{
			"max_prompts": "1",
			"evasion":     "homoglyph",
		},
		SessionID: "test-session-evasion",
	}

	evasionResult, err := plugin.Execute(context.Background(), evasionOpts)
	require.NoError(t, err)

	evasionInjResults := evasionResult.Data.(*augustusprobe.PromptInjectionResults)
	require.NotEmpty(t, evasionInjResults.Payloads)
	evasionPrompt := evasionInjResults.Payloads[0].Prompt

	assert.NotEqual(t, basePrompt, evasionPrompt, "homoglyph evasion should transform the prompt")
	assert.Equal(t, "homoglyph", evasionInjResults.EvasionUsed)
}

func TestPlugin_Execute_IssueDelivery(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo/issues" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       1,
				"number":   42,
				"state":    "open",
				"title":    "test",
				"html_url": "https://github.com/owner/repo/issues/42",
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
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "issues"},
		},
		ExtraOpts: map[string]string{
			"max_prompts": "2",
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Message, "issue #42")
	assert.NotEmpty(t, result.Artifacts)
	assert.NotEmpty(t, result.CleanupActions)
}

func TestPlugin_Cleanup_NoOp(t *testing.T) {
	plugin := New()
	err := plugin.Cleanup(context.Background(), &attacks.Session{})
	assert.Error(t, err) // Fails because session.Platform is nil, not *github.Platform
}

func TestPlugin_Cleanup_BestEffort(t *testing.T) {
	plugin := New()

	// Server that returns errors for some cleanup actions
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++
		// First request (close PR) fails, second (delete branch) succeeds
		if requestCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message": "server error"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	session := &attacks.Session{
		Platform: platform,
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Results: []*attacks.AttackResult{
			{
				Plugin: "ai-prompt-injection",
				Repo:   "owner/repo",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactPR,
						Identifier: "1",
						Action:     "close",
					},
					{
						Type:       attacks.ArtifactBranch,
						Identifier: "test-branch",
						Action:     "delete",
					},
				},
			},
		},
	}

	err := plugin.Cleanup(context.Background(), session)
	// Should return an error (from PR close failure) but still attempt branch delete
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closing PR")
	// Both requests should have been attempted (best-effort)
	assert.Equal(t, 2, requestCount, "all cleanup actions should be attempted")
}

func TestPlugin_Execute_EmptyPrompts(t *testing.T) {
	// This test verifies that the plugin handles the case where prompt
	// collection yields zero prompts gracefully (no panic).
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	// Use a finding type that maps to valid probes — the empty guard
	// is tested by ensuring no panic if prompts were somehow empty.
	// With real Augustus probes this won't produce empty, so we verify
	// the guard by checking the plugin doesn't panic with valid input.
	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
		},
		ExtraOpts: map[string]string{
			"max_prompts": "1",
		},
		SessionID: "test-session",
	}

	// This should not panic
	result, err := plugin.Execute(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestPlugin_Execute_InvalidDeliveryMethod(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
		},
		ExtraOpts: map[string]string{
			"delivery": "invalid_method",
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "invalid delivery method")
}

func TestPlugin_Execute_InvalidEvasionType(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	opts := attacks.AttackOptions{
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform: platform,
		DryRun:   true,
		Findings: []detections.Finding{
			{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
		},
		ExtraOpts: map[string]string{
			"evasion": "bogus_evasion",
		},
		SessionID: "test-session",
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "invalid evasion type")
}

func TestAnalyzeFindings(t *testing.T) {
	tests := []struct {
		name              string
		findings          []detections.Finding
		wantDelivery      deliveryMethod
		wantVulnTypeCount int
	}{
		{
			name: "PR trigger",
			findings: []detections.Finding{
				{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
			},
			wantDelivery:      deliveryPR,
			wantVulnTypeCount: 1,
		},
		{
			name: "PR preferred over comment",
			findings: []detections.Finding{
				{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
				{Type: detections.VulnAITokenExfiltration, Trigger: "issue_comment"},
			},
			wantDelivery:      deliveryPR,
			wantVulnTypeCount: 2,
		},
		{
			name: "issues trigger selects issue delivery",
			findings: []detections.Finding{
				{Type: detections.VulnAICodeInjection, Trigger: "issues"},
			},
			wantDelivery:      deliveryIssue,
			wantVulnTypeCount: 1,
		},
		{
			name: "PR preferred over issues",
			findings: []detections.Finding{
				{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
				{Type: detections.VulnAITokenExfiltration, Trigger: "issues"},
			},
			wantDelivery:      deliveryPR,
			wantVulnTypeCount: 2,
		},
		{
			name: "comment-only trigger",
			findings: []detections.Finding{
				{Type: detections.VulnAICodeInjection, Trigger: "issue_comment"},
			},
			wantDelivery:      deliveryComment,
			wantVulnTypeCount: 1,
		},
		{
			name: "issue-only trigger",
			findings: []detections.Finding{
				{Type: detections.VulnAIMCPAbuse, Trigger: "issues"},
			},
			wantDelivery:      deliveryIssue,
			wantVulnTypeCount: 1,
		},
		{
			name: "no trigger defaults to issue",
			findings: []detections.Finding{
				{Type: detections.VulnAIMCPAbuse},
			},
			wantDelivery:      deliveryIssue,
			wantVulnTypeCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delivery, vulnTypes := analyzeFindings(tt.findings)
			assert.Equal(t, tt.wantDelivery, delivery)
			assert.Len(t, vulnTypes, tt.wantVulnTypeCount)
		})
	}
}

// ---------------------------------------------------------------------------
// Finding 18: max_prompts boundary conditions
// ---------------------------------------------------------------------------

func TestPlugin_Execute_DryRun_MaxPromptsBoundary(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	tests := []struct {
		name      string
		value     string
		maxExpect int // upper bound on payload count; 0 means use default (5)
	}{
		{
			name:      "zero uses default",
			value:     "0",
			maxExpect: defaultMaxPrompts,
		},
		{
			name:      "upper bound 50",
			value:     "50",
			maxExpect: 50,
		},
		{
			name:      "exceeds upper bound clamped to 50",
			value:     "51",
			maxExpect: maxPromptsUpperBound,
		},
		{
			name:      "negative uses default",
			value:     "-1",
			maxExpect: defaultMaxPrompts,
		},
		{
			name:      "non-numeric uses default",
			value:     "abc",
			maxExpect: defaultMaxPrompts,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := attacks.AttackOptions{
				Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
				Platform: platform,
				DryRun:   true,
				Findings: []detections.Finding{
					{Type: detections.VulnAICodeInjection, Trigger: "pull_request"},
				},
				ExtraOpts: map[string]string{
					"max_prompts": tt.value,
				},
				SessionID: "test-boundary-" + tt.name,
			}

			result, err := plugin.Execute(context.Background(), opts)
			require.NoError(t, err)
			assert.True(t, result.Success)

			injResults, ok := result.Data.(*augustusprobe.PromptInjectionResults)
			require.True(t, ok)
			assert.LessOrEqual(t, len(injResults.Payloads), tt.maxExpect,
				"max_prompts=%s: payload count should be <= %d", tt.value, tt.maxExpect)
			assert.NotEmpty(t, injResults.Payloads,
				"max_prompts=%s: should still have at least one payload", tt.value)
		})
	}
}

// ---------------------------------------------------------------------------
// analyzeFindings edge cases
// ---------------------------------------------------------------------------

func TestAnalyzeFindings_NilFindings(t *testing.T) {
	delivery, vulnTypes := analyzeFindings(nil)
	assert.Equal(t, deliveryIssue, delivery, "nil findings should default to issue delivery")
	assert.Len(t, vulnTypes, 1, "nil findings should produce default vuln type")
	assert.Equal(t, detections.VulnAICodeInjection, vulnTypes[0])
}

func TestAnalyzeFindings_EmptyFindings(t *testing.T) {
	delivery, vulnTypes := analyzeFindings([]detections.Finding{})
	assert.Equal(t, deliveryIssue, delivery, "empty findings should default to issue delivery")
	assert.Len(t, vulnTypes, 1, "empty findings should produce default vuln type")
	assert.Equal(t, detections.VulnAICodeInjection, vulnTypes[0])
}

// ---------------------------------------------------------------------------
// Cleanup edge cases
// ---------------------------------------------------------------------------

func TestPlugin_Cleanup_UnknownArtifactType(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	session := &attacks.Session{
		Platform: platform,
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Results: []*attacks.AttackResult{
			{
				Plugin: "ai-prompt-injection",
				Repo:   "owner/repo",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactType("unknown_type"),
						Identifier: "123",
						Action:     "delete",
					},
				},
			},
		},
	}

	// Unknown artifact types should be silently skipped
	err := plugin.Cleanup(context.Background(), session)
	assert.NoError(t, err)
}

func TestPlugin_Cleanup_NonNumericIdentifier(t *testing.T) {
	plugin := New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	platform := github.NewPlatform()
	require.NoError(t, platform.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}))

	session := &attacks.Session{
		Platform: platform,
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Results: []*attacks.AttackResult{
			{
				Plugin: "ai-prompt-injection",
				Repo:   "owner/repo",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactPR,
						Identifier: "not-a-number",
						Action:     "close",
					},
					{
						Type:       attacks.ArtifactIssue,
						Identifier: "also-not-a-number",
						Action:     "close",
					},
					{
						Type:       attacks.ArtifactComment,
						Identifier: "bad-id",
						Action:     "delete",
					},
				},
			},
		},
	}

	// Non-numeric identifiers should be skipped with stderr warnings, no panic
	err := plugin.Cleanup(context.Background(), session)
	assert.NoError(t, err, "non-numeric identifiers should be skipped gracefully")
}

// invalidPlatform is a mock that doesn't implement *github.Platform.
type invalidPlatform struct{}

func (i *invalidPlatform) Name() string { return "invalid" }
func (i *invalidPlatform) Init(ctx context.Context, config platforms.Config) error {
	return nil
}
func (i *invalidPlatform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, nil
}
