// modules/trajan/pkg/analysis/flow/taint_test.go
package flow

import (
	"testing"
)

func TestTaintedValue(t *testing.T) {
	tv := NewTaintedValue(
		"user comment",
		TaintSourceUserInput,
		"github.event.comment.body",
	)

	if tv.Value != "user comment" {
		t.Errorf("Value = %q, want %q", tv.Value, "user comment")
	}
	if tv.Source != TaintSourceUserInput {
		t.Errorf("Source = %v, want %v", tv.Source, TaintSourceUserInput)
	}
	if len(tv.Path) != 1 {
		t.Errorf("Path length = %d, want 1", len(tv.Path))
	}
	if tv.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %v, want %v", tv.Confidence, ConfidenceHigh)
	}
}

func TestTaintPropagation(t *testing.T) {
	original := NewTaintedValue(
		"comment body",
		TaintSourceUserInput,
		"github.event.comment.body",
	)

	propagated := original.PropagateThrough("env.BODY")

	if propagated.Source != original.Source {
		t.Error("Source should be preserved through propagation")
	}
	if len(propagated.Path) != 2 {
		t.Errorf("Path length = %d, want 2", len(propagated.Path))
	}
	if propagated.Path[0] != "github.event.comment.body" {
		t.Errorf("Path[0] = %q, want %q", propagated.Path[0], "github.event.comment.body")
	}
	if propagated.Path[1] != "env.BODY" {
		t.Errorf("Path[1] = %q, want %q", propagated.Path[1], "env.BODY")
	}
}
