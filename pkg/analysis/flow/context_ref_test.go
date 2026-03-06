// modules/trajan/pkg/analysis/flow/context_ref_test.go
package flow

import "testing"

func TestPlatformContextRef(t *testing.T) {
	tests := []struct {
		name        string
		platform    string
		ref         string
		wantTainted bool
	}{
		// GitHub
		{
			name:        "GitHub PR title",
			platform:    "github",
			ref:         "github.event.pull_request.title",
			wantTainted: true,
		},
		{
			name:        "GitHub SHA (safe)",
			platform:    "github",
			ref:         "github.sha",
			wantTainted: false,
		},
		// GitLab
		{
			name:        "GitLab MR title",
			platform:    "gitlab",
			ref:         "CI_MERGE_REQUEST_TITLE",
			wantTainted: true,
		},
		{
			name:        "GitLab commit SHA (safe)",
			platform:    "gitlab",
			ref:         "CI_COMMIT_SHA",
			wantTainted: false,
		},
		// Azure DevOps
		{
			name:        "Azure PR title",
			platform:    "azure",
			ref:         "System.PullRequest.Title",
			wantTainted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewPlatformContextResolver(tt.platform)
			isTainted := resolver.IsTainted(tt.ref)
			if isTainted != tt.wantTainted {
				t.Errorf("IsTainted(%q) = %v, want %v", tt.ref, isTainted, tt.wantTainted)
			}
		})
	}
}
