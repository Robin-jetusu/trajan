package common

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/stretchr/testify/assert"
)

func TestInjectableContexts(t *testing.T) {
	// Verify expected injectable contexts are present
	expected := []string{
		"CI_MERGE_REQUEST_TITLE",
		"CI_MERGE_REQUEST_DESCRIPTION",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
		"CI_COMMIT_MESSAGE",
		"CI_COMMIT_DESCRIPTION",
		"CI_COMMIT_TITLE",
		"CI_COMMIT_TAG",
		"CI_COMMIT_REF_NAME",
		"CI_COMMIT_BRANCH",
		"CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME",
		"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
	}

	for _, ctx := range expected {
		assert.Contains(t, InjectableContexts, ctx, "Expected injectable context %s not found", ctx)
	}
}

func TestZeroClickTriggers(t *testing.T) {
	tests := []struct {
		name     string
		tag      graph.Tag
		expected bool
	}{
		{"merge request is zero-click", graph.TagMergeRequest, true},
		{"external pull request is zero-click", graph.TagExternalPullRequest, true},
		{"pipeline is zero-click", graph.TagPipeline, true},
		{"note is NOT zero-click", graph.TagNote, false},
		{"push is not zero-click", graph.TagPush, false},
		{"schedule is not zero-click", graph.TagSchedule, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ZeroClickTriggers[tt.tag]
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDangerousTokenVariables(t *testing.T) {
	// Verify expected dangerous token variables are present
	expected := []string{
		"CI_JOB_TOKEN",
		"CI_REGISTRY_PASSWORD",
		"CI_DEPLOY_PASSWORD",
		"CI_REPOSITORY_URL",
	}

	for _, token := range expected {
		assert.Contains(t, DangerousTokenVariables, token, "Expected token variable %s not found", token)
	}
}

func TestVariableExpressionRegex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple variable",
			input:    "echo $CI_COMMIT_MESSAGE",
			expected: []string{"$CI_COMMIT_MESSAGE"},
		},
		{
			name:     "braced variable",
			input:    "echo ${CI_MERGE_REQUEST_TITLE}",
			expected: []string{"${CI_MERGE_REQUEST_TITLE}"},
		},
		{
			name:     "multiple variables",
			input:    "$VAR1 and ${VAR2}",
			expected: []string{"$VAR1", "${VAR2}"},
		},
		{
			name:     "no variables",
			input:    "echo 'hello world'",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := VariableExpressionRegex.FindAllString(tt.input, -1)
			assert.Equal(t, tt.expected, matches)
		})
	}
}

func TestGetStepParentWorkflow(t *testing.T) {
	tests := []struct {
		name             string
		setupGraph       func() (*graph.Graph, *graph.StepNode)
		expectedWorkflow string
		expectedNil      bool
	}{
		{
			name: "valid step with parent job and workflow",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()

				// Create workflow -> job -> step hierarchy
				wf := graph.NewWorkflowNode("wf-1", "main-workflow", ".gitlab-ci.yml", "owner/repo", []string{"merge_request"})
				job := graph.NewJobNode("job-1", "build", "docker")
				step := graph.NewStepNode("step-1", "run tests", 10)

				g.AddNode(wf)
				g.AddNode(job)
				g.AddNode(step)

				// Establish containment edges: workflow -> job -> step
				g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)
				g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

				return g, step
			},
			expectedWorkflow: "wf-1",
			expectedNil:      false,
		},
		{
			name: "included workflow with step",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()

				// Create parent workflow
				parentWf := graph.NewWorkflowNode("wf-parent", "parent", ".gitlab-ci.yml", "owner/repo", []string{"push"})

				// Create included workflow -> job -> step hierarchy
				includedWf := graph.NewWorkflowNode("wf-included", "included-workflow", "included.yml", "owner/repo", []string{"merge_request"})
				job := graph.NewJobNode("job-included", "deploy", "docker")
				step := graph.NewStepNode("step-included", "deploy app", 20)

				g.AddNode(parentWf)
				g.AddNode(includedWf)
				g.AddNode(job)
				g.AddNode(step)

				// Establish hierarchy
				g.AddEdge(includedWf.ID(), job.ID(), graph.EdgeContains)
				g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

				// Establish include relationship
				g.AddEdge(parentWf.ID(), includedWf.ID(), graph.EdgeIncludes)

				return g, step
			},
			expectedWorkflow: "wf-included",
			expectedNil:      false,
		},
		{
			name: "nil step returns nil",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()
				return g, nil
			},
			expectedWorkflow: "",
			expectedNil:      true,
		},
		{
			name: "step with no parent job returns nil",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()

				// Create orphaned step (no parent)
				step := graph.NewStepNode("step-orphan", "orphaned step", 15)
				g.AddNode(step)

				return g, step
			},
			expectedWorkflow: "",
			expectedNil:      true,
		},
		{
			name: "job with no parent workflow returns nil",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()

				// Create job and step, but no workflow
				job := graph.NewJobNode("job-orphan", "orphaned job", "docker")
				step := graph.NewStepNode("step-1", "test", 10)

				g.AddNode(job)
				g.AddNode(step)

				// Connect step to job
				g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

				return g, step
			},
			expectedWorkflow: "",
			expectedNil:      true,
		},
		{
			name: "parent is not a workflow node returns nil",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()

				// Create step -> job -> action (invalid parent)
				action := graph.NewActionNode("action-1", "actions", "checkout", "v4")
				job := graph.NewJobNode("job-1", "build", "docker")
				step := graph.NewStepNode("step-1", "test", 10)

				g.AddNode(action)
				g.AddNode(job)
				g.AddNode(step)

				// Create invalid hierarchy: action -> job -> step
				g.AddEdge(action.ID(), job.ID(), graph.EdgeContains)
				g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

				return g, step
			},
			expectedWorkflow: "",
			expectedNil:      true,
		},
		{
			name: "multiple levels with correct traversal",
			setupGraph: func() (*graph.Graph, *graph.StepNode) {
				g := graph.NewGraph()

				// Create complex hierarchy
				wf := graph.NewWorkflowNode("wf-complex", "complex", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				job1 := graph.NewJobNode("job-1", "stage1", "docker")
				job2 := graph.NewJobNode("job-2", "stage2", "docker")
				step1 := graph.NewStepNode("step-1", "build", 10)
				step2 := graph.NewStepNode("step-2", "test", 20)

				g.AddNode(wf)
				g.AddNode(job1)
				g.AddNode(job2)
				g.AddNode(step1)
				g.AddNode(step2)

				// workflow contains both jobs
				g.AddEdge(wf.ID(), job1.ID(), graph.EdgeContains)
				g.AddEdge(wf.ID(), job2.ID(), graph.EdgeContains)

				// jobs contain steps
				g.AddEdge(job1.ID(), step1.ID(), graph.EdgeContains)
				g.AddEdge(job2.ID(), step2.ID(), graph.EdgeContains)

				// Both steps should resolve to the same workflow
				return g, step2
			},
			expectedWorkflow: "wf-complex",
			expectedNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, step := tt.setupGraph()
			result := GetStepParentWorkflow(g, step)

			if tt.expectedNil {
				assert.Nil(t, result, "Expected nil workflow")
			} else {
				assert.NotNil(t, result, "Expected non-nil workflow")
				assert.Equal(t, tt.expectedWorkflow, result.ID(), "Workflow ID mismatch")
			}
		})
	}
}

func TestIsRootWorkflow(t *testing.T) {
	tests := []struct {
		name       string
		setupGraph func() (*graph.Graph, *graph.WorkflowNode)
		expected   bool
	}{
		{
			name: "root workflow returns true",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()

				// Create main .gitlab-ci.yml workflow with no incoming includes
				wf := graph.NewWorkflowNode("wf-root", "main-workflow", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				job := graph.NewJobNode("job-1", "build", "docker")

				g.AddNode(wf)
				g.AddNode(job)

				// Workflow contains job (outgoing edge, not incoming)
				g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

				return g, wf
			},
			expected: true,
		},
		{
			name: "included workflow returns false",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()

				// Create parent workflow
				parentWf := graph.NewWorkflowNode("wf-parent", "parent", ".gitlab-ci.yml", "owner/repo", []string{"push"})

				// Create included workflow (build.yml)
				includedWf := graph.NewWorkflowNode("wf-included", "build-workflow", "build.yml", "owner/repo", []string{"push"})

				g.AddNode(parentWf)
				g.AddNode(includedWf)

				// Parent includes child - this creates an incoming EdgeIncludes edge to includedWf
				g.AddEdge(parentWf.ID(), includedWf.ID(), graph.EdgeIncludes)

				return g, includedWf
			},
			expected: false,
		},
		{
			name: "nil workflow returns false",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()
				return g, nil
			},
			expected: false,
		},
		{
			name: "workflow with no edges returns true",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()

				// Create isolated workflow with no edges at all
				wf := graph.NewWorkflowNode("wf-isolated", "isolated", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				g.AddNode(wf)

				return g, wf
			},
			expected: true,
		},
		{
			name: "workflow with outgoing edges only returns true",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()

				// Create workflow with only outgoing edges (contains, triggers)
				wf := graph.NewWorkflowNode("wf-outgoing", "main", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				job := graph.NewJobNode("job-1", "build", "docker")
				triggeredWf := graph.NewWorkflowNode("wf-triggered", "triggered", "deploy.yml", "owner/repo", []string{"push"})

				g.AddNode(wf)
				g.AddNode(job)
				g.AddNode(triggeredWf)

				// Outgoing edges (not incoming)
				g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)
				g.AddEdge(wf.ID(), triggeredWf.ID(), graph.EdgeTriggers)

				return g, wf
			},
			expected: true,
		},
		{
			name: "workflow with incoming non-includes edge returns true",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()

				// Create workflows with incoming trigger edge (not include)
				triggerWf := graph.NewWorkflowNode("wf-trigger", "trigger", "trigger.yml", "owner/repo", []string{"push"})
				targetWf := graph.NewWorkflowNode("wf-target", "target", "target.yml", "owner/repo", []string{"workflow_run"})

				g.AddNode(triggerWf)
				g.AddNode(targetWf)

				// Incoming EdgeTriggers (not EdgeIncludes) should still be root
				g.AddEdge(triggerWf.ID(), targetWf.ID(), graph.EdgeTriggers)

				return g, targetWf
			},
			expected: true,
		},
		{
			name: "workflow included by multiple parents returns false",
			setupGraph: func() (*graph.Graph, *graph.WorkflowNode) {
				g := graph.NewGraph()

				// Create multiple parent workflows
				parent1 := graph.NewWorkflowNode("wf-parent1", "parent1", ".gitlab-ci.yml", "owner/repo", []string{"push"})
				parent2 := graph.NewWorkflowNode("wf-parent2", "parent2", "other.yml", "owner/repo", []string{"push"})

				// Create shared included workflow
				sharedWf := graph.NewWorkflowNode("wf-shared", "shared", "shared.yml", "owner/repo", []string{"push"})

				g.AddNode(parent1)
				g.AddNode(parent2)
				g.AddNode(sharedWf)

				// Multiple parents include the same workflow
				g.AddEdge(parent1.ID(), sharedWf.ID(), graph.EdgeIncludes)
				g.AddEdge(parent2.ID(), sharedWf.ID(), graph.EdgeIncludes)

				return g, sharedWf
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, wf := tt.setupGraph()
			result := IsRootWorkflow(g, wf)
			assert.Equal(t, tt.expected, result)
		})
	}
}
