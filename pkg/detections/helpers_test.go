package detections

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/stretchr/testify/assert"
)

func TestBuildChainFromNodes_Empty(t *testing.T) {
	chain := BuildChainFromNodes()
	assert.Nil(t, chain)
}

// Mock node for testing - implements graph.Node interface
type mockNode struct {
	line     int
	name     string
	nodeType graph.NodeType
	ifCond   string
}

func (m *mockNode) ID() string                { return "mock" }
func (m *mockNode) Type() graph.NodeType      { return m.nodeType }
func (m *mockNode) HasTag(tag graph.Tag) bool { return false }
func (m *mockNode) AddTag(tag graph.Tag)      {}
func (m *mockNode) Tags() []graph.Tag         { return nil }
func (m *mockNode) Parent() string            { return "" }
func (m *mockNode) SetParent(id string)       {}
