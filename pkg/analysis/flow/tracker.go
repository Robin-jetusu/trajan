package flow

import (
	"context"
)

// Tracker performs variable flow analysis on a workflow graph
type Tracker struct {
	// Future: will hold reference to graph.Graph and expression.Evaluator
	// For now, minimal implementation to support resolver tests
}

// NewTracker creates a new flow tracker
func NewTracker() *Tracker {
	return &Tracker{}
}

// AnalyzeFlow performs flow analysis from trigger to injectable sinks
// Returns a map of node ID -> FlowContext
func (t *Tracker) AnalyzeFlow(ctx context.Context) (map[string]*FlowContext, error) {
	// Minimal implementation - will be expanded in future phases
	result := make(map[string]*FlowContext)
	return result, nil
}
