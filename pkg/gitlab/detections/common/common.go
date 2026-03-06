package common

import (
	"regexp"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// InjectableContexts are user-controllable GitLab CI predefined variables.
// These variables can be manipulated by external attackers through merge requests,
// commits, tags, or other user-controlled inputs.
var InjectableContexts = []string{
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

// ZeroClickTriggers are events that external attackers can trigger
// without requiring write access or human approval.
// Note: TagNote (comment events) is NOT a valid CI_PIPELINE_SOURCE in GitLab
// and cannot trigger pipelines natively.
var ZeroClickTriggers = map[graph.Tag]bool{
	graph.TagMergeRequest:        true,
	graph.TagExternalPullRequest: true,
	graph.TagPipeline:            true,
}

// DangerousTokenVariables are CI variables that expose sensitive tokens
// Using these in untrusted contexts can lead to privilege escalation
var DangerousTokenVariables = []string{
	"CI_JOB_TOKEN",
	"CI_REGISTRY_PASSWORD",
	"CI_DEPLOY_PASSWORD",
	"CI_REPOSITORY_URL", // Contains embedded credentials
}

// VariableExpressionRegex matches GitLab $VARIABLE and ${VARIABLE} patterns
var VariableExpressionRegex = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

// GetStepParentWorkflow finds the parent workflow node for a step.
// Traverses: Step -> Job -> Workflow
// Returns nil if:
// - step is nil
// - step has no parent job
// - job has no parent workflow
// - parent is not a WorkflowNode
func GetStepParentWorkflow(g *graph.Graph, step *graph.StepNode) *graph.WorkflowNode {
	if step == nil {
		return nil
	}

	// Get parent job
	jobNode, ok := g.GetNode(step.Parent())
	if !ok {
		return nil
	}

	// Get parent workflow
	wfNode, ok := g.GetNode(jobNode.Parent())
	if !ok {
		return nil
	}

	// Type assert to WorkflowNode
	if wf, ok := wfNode.(*graph.WorkflowNode); ok {
		return wf
	}

	return nil
}

// IsRootWorkflow returns true if the workflow is a root (not included by another workflow).
// Root workflows have no incoming EdgeIncludes edges.
// These are typically main .gitlab-ci.yml files or standalone workflow files.
// Workflows that are included via the 'include' keyword will have incoming EdgeIncludes edges
// and therefore are not roots.
func IsRootWorkflow(g *graph.Graph, wf *graph.WorkflowNode) bool {
	if wf == nil {
		return false
	}

	// Check for incoming EdgeIncludes edges
	for _, edge := range g.GetIncomingEdges(wf.ID()) {
		if edge.Type == graph.EdgeIncludes {
			return false // This workflow is included by another
		}
	}

	return true // No incoming includes, this is a root workflow
}
