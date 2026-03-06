//go:build integration
// +build integration

// pkg/gitlab/attacks/runnerexec/integration_test.go
package runnerexec

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestRunnerExec_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Requires environment variables:
	// - GITLAB_TOKEN: GitLab PAT with api scope
	// - GITLAB_TEST_PROJECT: Project path (e.g., "owner/repo")
	// - GITLAB_TEST_RUNNER_TAGS: Comma-separated tags (e.g., "integration-test,linux")

	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		t.Skip("GITLAB_TOKEN not set")
	}

	projectPath := os.Getenv("GITLAB_TEST_PROJECT")
	if projectPath == "" {
		t.Skip("GITLAB_TEST_PROJECT not set")
	}

	runnerTags := os.Getenv("GITLAB_TEST_RUNNER_TAGS")
	if runnerTags == "" {
		runnerTags = "integration-test"
	}

	ctx := context.Background()

	// Create platform via registry
	platform, err := registry.GetPlatform("gitlab")
	require.NoError(t, err)

	// Initialize platform
	err = platform.Init(ctx, platforms.Config{
		Token: token,
	})
	require.NoError(t, err)

	// Create plugin
	plugin := New()

	// Execute attack
	sessionID := uuid.New().String()[:8]
	opts := attacks.AttackOptions{
		Platform:  platform,
		Target:    platforms.Target{Value: projectPath, Type: platforms.TargetRepo},
		SessionID: sessionID,
		Timeout:   5 * time.Minute,
		ExtraOpts: map[string]string{
			"runner-tags": runnerTags,
			"command":     "echo 'integration-test-output'",
			"cleanup":     "true",
		},
	}

	result, err := plugin.Execute(ctx, opts)

	// Verify results
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.NotNil(t, result.Data)

	// Extract output from Data (which is a map[string]interface{})
	dataMap, ok := result.Data.(map[string]interface{})
	require.True(t, ok, "result.Data should be a map")
	output, ok := dataMap["output"].(string)
	require.True(t, ok, "output should be a string")
	assert.Contains(t, output, "integration-test-output")

	// Verify artifacts were tracked
	assert.NotEmpty(t, result.Artifacts)
	assert.NotEmpty(t, result.CleanupActions)

	// Note: Cleanup happens via defer in Execute, so artifacts should be gone
	// Could verify by checking branch doesn't exist, but that requires keeping branch name
}
