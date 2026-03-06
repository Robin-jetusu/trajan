// modules/trajan/pkg/analysis/flow/taint_tracker_test.go
package flow

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestTaintTracker(t *testing.T) {
	tt := NewTaintTracker()

	// Create a mock workflow graph
	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "test.yml", ".github/workflows/test.yml", "owner/repo", []string{"issue_comment"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step with tainted run command
	step := graph.NewStepNode("step1", "dangerous", 10)
	step.Run = "echo ${{ github.event.comment.body }}"
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	// Analyze
	ctx := context.Background()
	result, err := tt.Analyze(ctx, g)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Should detect taint at step1
	if stepCtx, ok := result["step1"]; ok {
		if len(stepCtx.TaintedExpressions) == 0 {
			t.Error("Expected tainted expressions in step context")
		}
	} else {
		t.Error("Expected flow context for step1")
	}
}
