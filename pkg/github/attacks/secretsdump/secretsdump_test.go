package secretsdump

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestSecretsDump_CanAttack(t *testing.T) {
	plugin := New()

	testCases := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name:     "with injection vulnerability",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: true,
		},
		{
			name:     "with pwn request vulnerability",
			findings: []detections.Finding{{Type: detections.VulnPwnRequest}},
			expected: true,
		},
		{
			name: "with both vulnerabilities",
			findings: []detections.Finding{
				{Type: detections.VulnActionsInjection},
				{Type: detections.VulnPwnRequest},
			},
			expected: true,
		},
		{
			name:     "with unrelated vulnerability",
			findings: []detections.Finding{{Type: detections.VulnSelfHostedRunner}},
			expected: false,
		},
		{
			name:     "with no vulnerabilities",
			findings: []detections.Finding{},
			expected: false,
		},
		{
			name:     "nil findings",
			findings: nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := plugin.CanAttack(tc.findings)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSecretsDump_Metadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "secrets-dump", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategorySecrets, plugin.Category())
}

func TestExecute_DryRun(t *testing.T) {
	plugin := New()

	mockPlatform := newMockGitHubPlatform(t)
	defer mockPlatform.Close()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  mockPlatform.Platform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(context.Background(), opts)
	assert.NoError(t, err, "Execute() should not error in dry run")
	assert.True(t, result.Success, "Execute() should succeed in dry run")
	assert.Contains(t, result.Message, "[DRY RUN]", "Message should indicate dry run")
	assert.Contains(t, result.Message, "encrypted secrets dump workflow", "Message should mention workflow")

	// Should have 2 artifacts: branch and workflow
	assert.Len(t, result.Artifacts, 2, "Should have 2 artifacts (branch, workflow)")

	// Verify artifact types
	artifactTypes := make(map[attacks.ArtifactType]bool)
	for _, artifact := range result.Artifacts {
		artifactTypes[artifact.Type] = true
	}
	assert.True(t, artifactTypes[attacks.ArtifactBranch], "Should have branch artifact")
	assert.True(t, artifactTypes[attacks.ArtifactWorkflow], "Should have workflow artifact")

	// Should have cleanup actions
	assert.Len(t, result.CleanupActions, 1, "Should have 1 cleanup action")
	assert.Equal(t, attacks.ArtifactBranch, result.CleanupActions[0].Type, "Cleanup should delete branch")
}

func TestExecute_InvalidPlatform(t *testing.T) {
	plugin := New()

	// Use a non-GitHub platform
	invalidPlatform := &invalidPlatform{}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  invalidPlatform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(context.Background(), opts)

	assert.Error(t, err, "Execute() should error for invalid platform")
	assert.NotNil(t, result, "Result should not be nil")
	assert.False(t, result.Success, "Execute() should fail for invalid platform")
	assert.Equal(t, "platform is not GitHub", result.Message, "Should have correct error message")
}

func TestExecute_BranchCreationFailed(t *testing.T) {
	plugin := New()

	// Use a mock server that returns an error for branch creation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return error for branch creation (POST to refs)
		if r.Method == "POST" && r.URL.Path == "/repos/owner/repo/git/refs" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"message": "Reference already exists"}`))
			return
		}
		// Default response for other requests
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    false, // Not a dry run so it tries to create branch
		SessionID: "test-session",
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(ctx, opts)

	assert.Error(t, err, "Execute() should error when branch creation fails")
	assert.NotNil(t, result, "Result should not be nil")
	assert.False(t, result.Success, "Execute() should fail when branch creation fails")
	assert.Contains(t, result.Message, "failed to create branch", "Should indicate branch creation failure")
}

func TestExecute_WorkflowCreationFailed(t *testing.T) {
	plugin := New()

	// Use a mock server that returns an error for workflow file creation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Success for branch creation (POST to refs)
		if r.Method == "POST" && r.URL.Path == "/repos/owner/repo/git/refs" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"ref": "refs/heads/test-branch", "object": {"sha": "abc123"}}`))
			return
		}
		// Error for file creation (PUT to contents)
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message": "Resource protected"}`))
			return
		}
		// Default response for other requests
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    false, // Not a dry run so it tries to create workflow
		SessionID: "test-session",
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(ctx, opts)

	assert.Error(t, err, "Execute() should error when workflow creation fails")
	assert.NotNil(t, result, "Result should not be nil")
	assert.False(t, result.Success, "Execute() should fail when workflow creation fails")
	assert.Contains(t, result.Message, "failed to create workflow", "Should indicate workflow creation failure")
}

// Mock implementations for testing

type mockPlatform struct {
	*github.Platform
	server *httptest.Server
}

func newMockGitHubPlatform(t *testing.T) *mockPlatform {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
	}))

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	return &mockPlatform{
		Platform: platform,
		server:   server,
	}
}

func (m *mockPlatform) Close() {
	m.server.Close()
}

func TestExecute_RealMode_Success(t *testing.T) {
	plugin := New()

	// Create mock server with comprehensive API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo":
			// Repository info
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
		case r.URL.Path == "/repos/owner/repo/git/refs/heads/main":
			// Default branch SHA
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"object": {"sha": "abc123def456"}}`))
		case r.URL.Path == "/repos/owner/repo/git/refs" && r.Method == "POST":
			// Branch creation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"ref": "refs/heads/trajan-attack-test-session", "object": {"sha": "abc123def456"}}`))
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/trajan-secrets-dump.yml" && r.Method == "PUT":
			// Workflow file creation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"content": {"name": "trajan-secrets-dump.yml", "path": ".github/workflows/trajan-secrets-dump.yml"}}`))
		case r.URL.Path == "/repos/owner/repo/actions/runs":
			// Workflow runs list
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"total_count": 1,
				"workflow_runs": [
					{
						"id": 999,
						"name": "secrets dump workflow",
						"head_branch": "trajan-attack-test-session",
						"head_sha": "abc123def456",
						"status": "queued",
						"conclusion": null,
						"created_at": "2024-01-01T00:00:00Z"
					}
				]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    false, // IMPORTANT: Not dry-run
		SessionID: "test-session",
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(ctx, opts)
	assert.NoError(t, err, "Execute() should not error in real mode")
	assert.True(t, result.Success, "Execute() should succeed in real mode")

	// Should have 2 artifacts: branch and workflow
	assert.Len(t, result.Artifacts, 2, "Should have 2 artifacts (branch, workflow)")

	// Verify artifact types
	artifactTypes := make(map[attacks.ArtifactType]bool)
	for _, artifact := range result.Artifacts {
		artifactTypes[artifact.Type] = true
	}
	assert.True(t, artifactTypes[attacks.ArtifactBranch], "Should have branch artifact")
	assert.True(t, artifactTypes[attacks.ArtifactWorkflow], "Should have workflow artifact")

	// CRITICAL: CleanupActions should be set in real mode
	assert.Len(t, result.CleanupActions, 1, "Should have 1 cleanup action in real mode")
	assert.Equal(t, attacks.ArtifactBranch, result.CleanupActions[0].Type, "Cleanup should delete branch")

	// Verify result data contains private key for decryption
	assert.NotNil(t, result.Data, "Result data should not be nil")
	dataMap, ok := result.Data.(map[string]interface{})
	assert.True(t, ok, "Result data should be a map")

	privateKeyPEM, ok := dataMap["private_key_pem"]
	assert.True(t, ok, "Result data should contain private_key_pem")
	assert.NotEmpty(t, privateKeyPEM, "Private key PEM should not be empty")

	// Verify workflow run ID was captured
	runID, ok := dataMap["run_id"]
	assert.True(t, ok, "Result data should contain run_id")
	assert.Equal(t, int64(999), runID, "Run ID should match mock response")
}

func TestCleanup_BranchDeletion(t *testing.T) {
	plugin := New()

	// Track API calls
	var deletedBranch string

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo/git/refs/heads/trajan-attack-test-session" && r.Method == "DELETE":
			// Branch deletion
			deletedBranch = "trajan-attack-test-session"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	// Create a session with a branch cleanup action
	session := &attacks.Session{
		Platform: platform,
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Results: []*attacks.AttackResult{
			{
				Plugin: "secrets-dump",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:        attacks.ArtifactBranch,
						Identifier:  "trajan-attack-test-session",
						Action:      "delete",
						Description: "Delete attack branch",
					},
				},
			},
		},
	}

	// Execute cleanup
	err := plugin.Cleanup(ctx, session)
	assert.NoError(t, err, "Cleanup() should not error")

	// Verify the branch was deleted
	assert.Equal(t, "trajan-attack-test-session", deletedBranch, "Branch should be deleted")
}

type invalidPlatform struct{}

func (i *invalidPlatform) Name() string {
	return "invalid"
}

func (i *invalidPlatform) Init(ctx context.Context, config platforms.Config) error {
	return nil
}

func (i *invalidPlatform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, nil
}
