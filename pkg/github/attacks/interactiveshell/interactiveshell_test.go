package interactiveshell

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestNew(t *testing.T) {
	plugin := New()

	assert.NotNil(t, plugin)
	assert.Equal(t, "interactive-shell", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryC2, plugin.Category())
	assert.Equal(t, 30, plugin.timeout)
}

func TestInteractiveShell_CanAttack(t *testing.T) {
	plugin := New()

	testCases := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name:     "always returns true",
			findings: []detections.Finding{},
			expected: true,
		},
		{
			name:     "with any findings",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: true,
		},
		{
			name:     "nil findings",
			findings: nil,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := plugin.CanAttack(tc.findings)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestInteractiveShell_Execute_MissingC2Repo(t *testing.T) {
	plugin := New()

	// Create a mock GitHub platform
	mockPlatform := &github.Platform{}

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Target: platforms.Target{
			Type:  platforms.TargetRepo,
			Value: "test/repo",
		},
		Platform:  mockPlatform,
		ExtraOpts: map[string]string{},
	}

	result, err := plugin.Execute(context.Background(), opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "c2_repo is required")
}

func TestInteractiveShell_Execute_InvalidPlatform(t *testing.T) {
	plugin := New()

	opts := attacks.AttackOptions{
		SessionID: "test-session",
		Target: platforms.Target{
			Type:  platforms.TargetRepo,
			Value: "test/repo",
		},
		Platform:  nil,
		ExtraOpts: map[string]string{"c2_repo": "test/c2"},
	}

	result, err := plugin.Execute(context.Background(), opts)

	require.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "platform is not GitHub")
}

func TestInteractiveShell_Cleanup(t *testing.T) {
	plugin := New()

	session := &attacks.Session{
		ID: "test-session",
		Results: []*attacks.AttackResult{
			{
				Plugin:    plugin.Name(),
				SessionID: "test-session",
			},
		},
	}

	err := plugin.Cleanup(context.Background(), session)

	// Cleanup should succeed with no operations
	assert.NoError(t, err)
}

func TestParseCommandOutput(t *testing.T) {
	testCases := []struct {
		name     string
		logs     []byte
		expected string
	}{
		{
			name: "simple command output",
			logs: []byte(`
2024-01-01T00:00:00.0000000Z ##[group]Run echo "Hello World"
2024-01-01T00:00:01.0000000Z Hello World
2024-01-01T00:00:02.0000000Z ##[endgroup]
`),
			expected: "Hello World\n",
		},
		{
			name: "multi-line output",
			logs: []byte(`
2024-01-01T00:00:00.0000000Z ##[group]Run ls -la
2024-01-01T00:00:01.0000000Z total 8
2024-01-01T00:00:02.0000000Z drwxr-xr-x  2 runner runner 4096 Jan 1 00:00 .
2024-01-01T00:00:03.0000000Z drwxr-xr-x  3 runner runner 4096 Jan 1 00:00 ..
2024-01-01T00:00:04.0000000Z ##[endgroup]
`),
			expected: "total 8\ndrwxr-xr-x  2 runner runner 4096 Jan 1 00:00 .\ndrwxr-xr-x  3 runner runner 4096 Jan 1 00:00 ..\n",
		},
		{
			name:     "empty logs",
			logs:     []byte(""),
			expected: "",
		},
		{
			name: "logs with no command output",
			logs: []byte(`
2024-01-01T00:00:00.0000000Z ##[group]Setup
2024-01-01T00:00:01.0000000Z ##[endgroup]
`),
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseCommandOutput(tc.logs)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMetadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "interactive-shell", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, "github", plugin.Platform())
	assert.Equal(t, attacks.CategoryC2, plugin.Category())
}
