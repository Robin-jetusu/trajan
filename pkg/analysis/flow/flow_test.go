package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVariableResolution tests resolving variables through multiple levels
func TestVariableResolution(t *testing.T) {
	tests := []struct {
		name     string
		variable string
		env      map[string]string
		inputs   map[string]string
		want     string
		wantOK   bool
	}{
		{
			name:     "direct github context",
			variable: "github.event.comment.body",
			want:     "github.event.comment.body",
			wantOK:   true,
		},
		{
			name:     "env to github",
			variable: "env.COMMENT_BODY",
			env:      map[string]string{"COMMENT_BODY": "${{ github.event.comment.body }}"},
			want:     "github.event.comment.body",
			wantOK:   true,
		},
		{
			name:     "input to env to github",
			variable: "inputs.body",
			inputs:   map[string]string{"body": "${{ env.COMMENT_BODY }}"},
			env:      map[string]string{"COMMENT_BODY": "${{ github.event.comment.body }}"},
			want:     "github.event.comment.body",
			wantOK:   true,
		},
		{
			name:     "input to github directly",
			variable: "inputs.title",
			inputs:   map[string]string{"title": "${{ github.event.pull_request.title }}"},
			want:     "github.event.pull_request.title",
			wantOK:   true,
		},
		{
			name:     "env to env chain",
			variable: "env.VAR1",
			env: map[string]string{
				"VAR1": "${{ env.VAR2 }}",
				"VAR2": "${{ github.event.issue.title }}",
			},
			want:   "github.event.issue.title",
			wantOK: true,
		},
		{
			name:     "unresolvable variable",
			variable: "steps.build.outputs.result",
			want:     "steps.build.outputs.result",
			wantOK:   false,
		},
		{
			name:     "unknown context",
			variable: "secrets.TOKEN",
			want:     "secrets.TOKEN",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FlowContext{
				InputLookup:  tt.inputs,
				EnvLookup:    tt.env,
				StepOutputs:  make(map[string]string),
				ApprovalGate: false,
			}
			tracker := &Tracker{}
			got, ok := tracker.ResolveVariable(tt.variable, fc)
			assert.Equal(t, tt.want, got, "resolved variable should match")
			assert.Equal(t, tt.wantOK, ok, "resolution status should match")
		})
	}
}

// TestFlowContextCreation tests FlowContext initialization
func TestFlowContextCreation(t *testing.T) {
	fc := NewFlowContext()

	require.NotNil(t, fc)
	assert.NotNil(t, fc.InputLookup)
	assert.NotNil(t, fc.EnvLookup)
	assert.NotNil(t, fc.StepOutputs)
	assert.False(t, fc.ApprovalGate)
	assert.Empty(t, fc.GateDetails)
}

// TestFlowContextMergeEnv tests merging environment variables
func TestFlowContextMergeEnv(t *testing.T) {
	fc := NewFlowContext()

	// Simulate workflow-level env
	workflowEnv := map[string]string{
		"WORKFLOW_VAR": "${{ github.event.pull_request.head.ref }}",
	}
	fc.MergeEnv(workflowEnv)
	assert.Equal(t, "${{ github.event.pull_request.head.ref }}", fc.EnvLookup["WORKFLOW_VAR"])

	// Simulate job-level env (should override)
	jobEnv := map[string]string{
		"WORKFLOW_VAR": "${{ github.event.pull_request.base.ref }}", // Override
		"JOB_VAR":      "${{ github.event.comment.body }}",
	}
	fc.MergeEnv(jobEnv)
	assert.Equal(t, "${{ github.event.pull_request.base.ref }}", fc.EnvLookup["WORKFLOW_VAR"])
	assert.Equal(t, "${{ github.event.comment.body }}", fc.EnvLookup["JOB_VAR"])
}

// TestResolveVariableWithStepOutputs tests resolving step outputs
func TestResolveVariableWithStepOutputs(t *testing.T) {
	fc := &FlowContext{
		InputLookup: make(map[string]string),
		EnvLookup:   make(map[string]string),
		StepOutputs: map[string]string{
			"get-pr.result": "${{ github.event.pull_request.body }}",
		},
		ApprovalGate: false,
	}

	tracker := &Tracker{}

	// Test direct step output access
	resolved, ok := tracker.ResolveVariable("steps.get-pr.outputs.result", fc)
	assert.True(t, ok)
	assert.Equal(t, "github.event.pull_request.body", resolved)
}

// TestGateDetection tests gate information tracking
func TestGateDetection(t *testing.T) {
	fc := NewFlowContext()

	gate := GateInfo{
		Type:        GateDeploymentApproval,
		Location:    "job-deploy",
		Confidence:  ConfidenceHigh,
		Description: "Job uses deployment environment",
	}

	fc.AddGate(gate)

	assert.True(t, fc.ApprovalGate)
	assert.Len(t, fc.GateDetails, 1)
	assert.Equal(t, GateDeploymentApproval, fc.GateDetails[0].Type)
}

// TestExpressionExtraction tests extracting variable name from ${{ }}
func TestExpressionExtraction(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple context",
			input: "${{ github.event.comment.body }}",
			want:  "github.event.comment.body",
		},
		{
			name:  "with whitespace",
			input: "${{   github.event.issue.title   }}",
			want:  "github.event.issue.title",
		},
		{
			name:  "env variable",
			input: "${{ env.MY_VAR }}",
			want:  "env.MY_VAR",
		},
		{
			name:  "input variable",
			input: "${{ inputs.title }}",
			want:  "inputs.title",
		},
		{
			name:  "no expression",
			input: "plain text",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVariableName(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCircularReference tests handling circular variable references
func TestCircularReference(t *testing.T) {
	fc := &FlowContext{
		InputLookup: make(map[string]string),
		EnvLookup: map[string]string{
			"VAR1": "${{ env.VAR2 }}",
			"VAR2": "${{ env.VAR1 }}", // Circular!
		},
		StepOutputs:  make(map[string]string),
		ApprovalGate: false,
	}

	tracker := &Tracker{}

	// Should detect circular reference and stop
	resolved, ok := tracker.ResolveVariable("env.VAR1", fc)
	assert.False(t, ok, "should detect circular reference")
	assert.Contains(t, resolved, "env.VAR", "should return partial resolution")
}

// TestExitCriteria_TransitiveTaint tests exit criterion:
// "Identifies transitive taint through variable chains"
func TestExitCriteria_TransitiveTaint(t *testing.T) {
	t.Run("inputs.title -> env.PR_TITLE -> github.event.pull_request.title", func(t *testing.T) {
		fc := &FlowContext{
			InputLookup: map[string]string{
				"title": "${{ env.PR_TITLE }}",
			},
			EnvLookup: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			StepOutputs: make(map[string]string),
		}

		tracker := &Tracker{}
		resolved, ok := tracker.ResolveVariable("inputs.title", fc)

		require.True(t, ok, "should resolve successfully")
		assert.Equal(t, "github.event.pull_request.title", resolved,
			"should resolve through inputs -> env -> github chain")
	})

	t.Run("three-level chain", func(t *testing.T) {
		fc := &FlowContext{
			InputLookup: map[string]string{
				"param": "${{ env.LEVEL1 }}",
			},
			EnvLookup: map[string]string{
				"LEVEL1": "${{ env.LEVEL2 }}",
				"LEVEL2": "${{ github.event.comment.body }}",
			},
			StepOutputs: make(map[string]string),
		}

		tracker := &Tracker{}
		resolved, ok := tracker.ResolveVariable("inputs.param", fc)

		require.True(t, ok, "should resolve successfully")
		assert.Equal(t, "github.event.comment.body", resolved,
			"should resolve through three-level chain")
	})
}

// TestConfidenceLevels tests confidence enum values
func TestConfidenceLevels(t *testing.T) {
	assert.NotEqual(t, ConfidenceHigh, ConfidenceMedium)
	assert.NotEqual(t, ConfidenceMedium, ConfidenceLow)
	assert.NotEqual(t, ConfidenceHigh, ConfidenceLow)
}

// TestGateTypes tests gate type enum values
func TestGateTypes(t *testing.T) {
	assert.NotEqual(t, GateDeploymentApproval, GatePermissionCheck)
	assert.NotEqual(t, GatePermissionCheck, GateLabelRequired)
	assert.NotEqual(t, GateLabelRequired, GateAuthorAssociation)
}
