package injection

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestInjectionPlugin_DetectsIssueComment(t *testing.T) {
	yaml := `
name: Comment Handler
on: issue_comment
jobs:
  handle:
    runs-on: ubuntu-latest
    steps:
      - name: Process comment
        run: echo "${{ github.event.comment.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "comment.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnActionsInjection, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "github.event.comment.body")
}

func TestInjectionPlugin_IgnoresSafe(t *testing.T) {
	yaml := `
name: Safe Workflow
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"
`
	g, err := analysis.BuildGraph("owner/repo", "safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

func TestInjectionPlugin_Properties(t *testing.T) {
	p := New()
	assert.Equal(t, "actions-injection", p.Name())
	assert.Equal(t, "github", p.Platform())
	assert.Equal(t, detections.SeverityHigh, p.Severity())
}

// Edge case: Multiple injectable contexts in one step
func TestInjectionPlugin_MultipleInjectionsInStep(t *testing.T) {
	yaml := `
name: Multi Injection
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }} ${{ github.event.comment.body }}"
`
	g, err := analysis.BuildGraph("owner/repo", "multi.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Implementation creates one finding per step with all injectable contexts
	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnActionsInjection, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "github.event.issue.title")
	assert.Contains(t, findings[0].Evidence, "github.event.comment.body")
}

// Edge case: Non-zero-click trigger (should not escalate)
func TestInjectionPlugin_NonZeroClickTrigger(t *testing.T) {
	yaml := `
name: Push Handler
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.head_commit.message }}"
`
	g, err := analysis.BuildGraph("owner/repo", "push.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	// Should NOT be escalated (push is not zero-click)
	assert.Equal(t, detections.ConfidenceMedium, findings[0].Confidence)
	assert.Equal(t, detections.ComplexityMedium, findings[0].Complexity)
}

// Edge case: Nested expressions with injectable context
func TestInjectionPlugin_NestedExpressions(t *testing.T) {
	yaml := `
name: Nested Expression
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ contains(github.event.comment.body, 'test') }}"
`
	g, err := analysis.BuildGraph("owner/repo", "nested.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Should detect github.event.comment.body within contains()
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Evidence, "github.event.comment.body")
}

// Edge case: Multiple steps, only one with injection
func TestInjectionPlugin_MultipleSteps(t *testing.T) {
	yaml := `
name: Multiple Steps
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "safe step"
      - run: echo "${{ github.event.comment.body }}"
      - run: echo "another safe step"
`
	g, err := analysis.BuildGraph("owner/repo", "multistep.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Should find exactly 1 injection
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Evidence, "github.event.comment.body")
}

// Edge case: Empty workflow (no steps)
func TestInjectionPlugin_EmptyWorkflow(t *testing.T) {
	yaml := `
name: Empty
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
`
	g, err := analysis.BuildGraph("owner/repo", "empty.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	// Should handle gracefully
	assert.Len(t, findings, 0)
}

// Edge case: Graph with cycle (should not infinite loop)
func TestInjectionPlugin_GraphWithCycle(t *testing.T) {
	// Manually create a graph with a cycle using EdgeContains
	// This tests cycle detection in the traversal
	g := graph.NewGraph()

	// Create workflow node
	wf := graph.NewWorkflowNode("wf1", "Cycle Test", "cycle.yml", "owner/repo", []string{"issue_comment"})
	wf.AddTag(graph.TagIssueComment)
	g.AddNode(wf)

	// Create job nodes
	job1 := graph.NewJobNode("job1", "test-job-1", "ubuntu-latest")
	g.AddNode(job1)
	g.AddEdge(wf.ID(), job1.ID(), graph.EdgeContains)

	job2 := graph.NewJobNode("job2", "test-job-2", "ubuntu-latest")
	g.AddNode(job2)

	// Create cycle: job1 -> job2 -> job1 (both using EdgeContains)
	g.AddEdge(job1.ID(), job2.ID(), graph.EdgeContains)
	g.AddEdge(job2.ID(), job1.ID(), graph.EdgeContains)

	// Add an injectable step (not reachable due to cycle)
	step := graph.NewStepNode("step1", "Injectable Step", 10)
	step.Run = "echo \"${{ github.event.comment.body }}\""
	g.AddNode(step)
	g.AddEdge(job2.ID(), step.ID(), graph.EdgeContains)

	plugin := New()

	// This should complete without hanging (with timeout as safety)
	done := make(chan bool)
	go func() {
		_, err := plugin.Detect(context.Background(), g)
		require.NoError(t, err)
		// With proper cycle detection, should complete without hanging
		done <- true
	}()

	select {
	case <-done:
		// Test passed - completed without hanging
	case <-time.After(2 * time.Second):
		t.Fatal("Test timed out - infinite loop detected")
	}
}
