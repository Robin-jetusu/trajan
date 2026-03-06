// pkg/analysis/graph/node_test.go
package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode_AddTag(t *testing.T) {
	node := &WorkflowNode{
		BaseNode: BaseNode{
			id:   "test-node",
			tags: make(map[Tag]struct{}),
		},
	}

	node.AddTag(TagPullRequestTarget)
	node.AddTag(TagIssueComment)

	assert.True(t, node.HasTag(TagPullRequestTarget))
	assert.True(t, node.HasTag(TagIssueComment))
	assert.False(t, node.HasTag(TagCheckout))
}

func TestNodeType_Values(t *testing.T) {
	assert.Equal(t, NodeType("workflow"), NodeTypeWorkflow)
	assert.Equal(t, NodeType("job"), NodeTypeJob)
	assert.Equal(t, NodeType("step"), NodeTypeStep)
	assert.Equal(t, NodeType("action"), NodeTypeAction)
}

func TestNode_Type(t *testing.T) {
	wf := NewWorkflowNode("wf1", "Build", "build.yml", "owner/repo", []string{"push"})
	assert.Equal(t, NodeTypeWorkflow, wf.Type())

	job := NewJobNode("job1", "build", "ubuntu-latest")
	assert.Equal(t, NodeTypeJob, job.Type())

	step := NewStepNode("step1", "Checkout", 10)
	assert.Equal(t, NodeTypeStep, step.Type())

	action := NewActionNode("action1", "actions", "checkout", "v4")
	assert.Equal(t, NodeTypeAction, action.Type())
}

func TestNode_Parent(t *testing.T) {
	job := NewJobNode("job1", "build", "ubuntu-latest")

	assert.Equal(t, "", job.Parent())

	job.SetParent("wf1")
	assert.Equal(t, "wf1", job.Parent())
}

func TestNewActionNode(t *testing.T) {
	action := NewActionNode("action1", "actions", "checkout", "v4")

	assert.Equal(t, "action1", action.ID())
	assert.Equal(t, NodeTypeAction, action.Type())
	assert.Equal(t, "actions", action.Owner)
	assert.Equal(t, "checkout", action.Repo)
	assert.Equal(t, "v4", action.Ref)
	assert.Empty(t, action.Path)
}

func TestNode_AddTag_NilMap(t *testing.T) {
	// Test the nil map initialization branch
	node := &BaseNode{
		id:       "test",
		nodeType: NodeTypeWorkflow,
		tags:     nil, // explicitly nil
	}

	// Should not panic, should initialize map
	node.AddTag(TagPush)

	assert.True(t, node.HasTag(TagPush))
}
