// modules/trajan/pkg/detections/shared/unpinned/detector_test.go
package unpinned

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections/shared"
)

func TestUnpinnedDetector(t *testing.T) {
	resolver := shared.NewGitHubUsesResolver()
	validator := shared.NewGitHubPinValidator()
	detector := New(resolver, validator)

	wf := &graph.WorkflowNode{
		RepoSlug: "owner/repo",
		Name:     "test.yml",
	}
	ctx := shared.NewDetectionContext("github", wf)

	tests := []struct {
		name     string
		uses     string
		wantFind bool
	}{
		{
			name:     "unpinned action",
			uses:     "actions/checkout@v3",
			wantFind: true,
		},
		{
			name:     "pinned action",
			uses:     "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
			wantFind: false,
		},
		{
			name:     "local action",
			uses:     "./.github/actions/my-action",
			wantFind: false,
		},
		{
			name:     "docker image",
			uses:     "docker://alpine:3.18",
			wantFind: false, // Docker pinning is platform-specific
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := &graph.StepNode{
				Name: "test-step",
				Uses: tt.uses,
				Line: 10,
			}

			finding := detector.Detect(step, ctx)
			gotFind := finding != nil

			if gotFind != tt.wantFind {
				t.Errorf("Detect() returned finding = %v, want %v", gotFind, tt.wantFind)
			}
		})
	}
}
