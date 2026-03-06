// modules/trajan/pkg/analysis/flow/context_test.go
package flow

import "testing"

func TestFlowContextTaintTracking(t *testing.T) {
	fc := NewFlowContext()

	// Add a tainted value
	tv := NewTaintedValue("malicious", TaintSourceUserInput, "github.event.comment.body")
	fc.AddTaint("comment_body", tv)

	// Retrieve taint
	retrieved := fc.GetTaint("comment_body")
	if retrieved == nil {
		t.Fatal("GetTaint() returned nil, expected tainted value")
	}
	if retrieved.Source != TaintSourceUserInput {
		t.Errorf("Source = %v, want %v", retrieved.Source, TaintSourceUserInput)
	}

	// Check if tainted
	if !fc.IsTainted("comment_body") {
		t.Error("IsTainted() = false, want true")
	}

	// Non-tainted variable
	if fc.IsTainted("nonexistent") {
		t.Error("IsTainted(nonexistent) = true, want false")
	}
}
