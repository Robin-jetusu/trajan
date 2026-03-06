package enumerate

import (
	"testing"
	"time"

	"github.com/praetorian-inc/trajan/pkg/github"
)

// TestOutputSecretsConsole tests the console output formatting for secrets enumeration
func TestOutputSecretsConsole(t *testing.T) {
	tests := []struct {
		name   string
		result *github.SecretsResult
	}{
		{
			name: "repo with actions secrets",
			result: &github.SecretsResult{
				ActionsSecrets: map[string][]github.Secret{
					"owner/repo": {
						{Name: "AWS_KEY", CreatedAt: parseTime("2024-01-15")},
						{Name: "DB_PASSWORD", CreatedAt: parseTime("2024-02-20")},
					},
				},
				WorkflowSecrets:   map[string][]github.Secret{},
				DependabotSecrets: map[string][]github.Secret{},
				CodespacesSecrets: map[string][]github.Secret{},
			},
		},
		{
			name: "org with multiple secret types",
			result: &github.SecretsResult{
				ActionsSecrets: map[string][]github.Secret{
					"myorg": {
						{Name: "ORG_SECRET_1"},
						{Name: "ORG_SECRET_2"},
					},
				},
				DependabotSecrets: map[string][]github.Secret{
					"myorg": {
						{Name: "NPM_TOKEN"},
					},
				},
				CodespacesSecrets: map[string][]github.Secret{
					"myorg": {
						{Name: "DOTFILES_REPO"},
					},
				},
				WorkflowSecrets: map[string][]github.Secret{},
			},
		},
		{
			name: "empty result",
			result: &github.SecretsResult{
				ActionsSecrets:    map[string][]github.Secret{},
				WorkflowSecrets:   map[string][]github.Secret{},
				DependabotSecrets: map[string][]github.Secret{},
				CodespacesSecrets: map[string][]github.Secret{},
			},
		},
		{
			name: "with permission errors",
			result: &github.SecretsResult{
				ActionsSecrets: map[string][]github.Secret{
					"owner/repo": {
						{Name: "SECRET_1"},
					},
				},
				WorkflowSecrets:   map[string][]github.Secret{},
				DependabotSecrets: map[string][]github.Secret{},
				CodespacesSecrets: map[string][]github.Secret{},
				PermissionErrors:  []string{"owner/restricted-repo: 403 Forbidden"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call outputSecretsConsole to ensure it doesn't panic
			err := outputSecretsConsole(tt.result)

			if err != nil {
				t.Errorf("outputSecretsConsole() returned error: %v", err)
			}
		})
	}
}

// TestCountSecrets tests counting secrets across all types
func TestCountSecrets(t *testing.T) {
	result := &github.SecretsResult{
		ActionsSecrets: map[string][]github.Secret{
			"repo1": {{Name: "S1"}, {Name: "S2"}},
			"repo2": {{Name: "S3"}},
		},
		DependabotSecrets: map[string][]github.Secret{
			"repo1": {{Name: "D1"}},
		},
		CodespacesSecrets: map[string][]github.Secret{
			"repo1": {{Name: "C1"}, {Name: "C2"}},
		},
		WorkflowSecrets: map[string][]github.Secret{},
	}

	counts := countSecrets(result)

	if counts.Actions != 3 {
		t.Errorf("Actions count = %d, want 3", counts.Actions)
	}
	if counts.Dependabot != 1 {
		t.Errorf("Dependabot count = %d, want 1", counts.Dependabot)
	}
	if counts.Codespaces != 2 {
		t.Errorf("Codespaces count = %d, want 2", counts.Codespaces)
	}
	if counts.Total != 6 {
		t.Errorf("Total count = %d, want 6", counts.Total)
	}
}

// Helper to parse time for tests
func parseTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}
