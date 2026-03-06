// pkg/analysis/expression/taint_test.go
package expression

import (
	"strings"
	"testing"
)

func TestGetTaintInfo(t *testing.T) {
	eval := NewEvaluator()

	tests := []struct {
		name      string
		expr      string
		wantTaint bool
		sources   []string
	}{
		{
			name:      "Tainted PR title",
			expr:      "${{ github.event.pull_request.title }}",
			wantTaint: true,
			sources:   []string{"github.event.pull_request.title"},
		},
		{
			name:      "Safe SHA",
			expr:      "${{ github.sha }}",
			wantTaint: false,
			sources:   []string{},
		},
		{
			name:      "Mixed tainted and safe",
			expr:      "${{ github.event.issue.title && github.sha }}",
			wantTaint: true,
			sources:   []string{"github.event.issue.title"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := eval.Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			info := eval.GetTaintInfo(parsed)
			if info.IsTainted != tt.wantTaint {
				t.Errorf("IsTainted = %v, want %v", info.IsTainted, tt.wantTaint)
			}

			if len(info.Sources) != len(tt.sources) {
				t.Errorf("Sources count = %d, want %d", len(info.Sources), len(tt.sources))
			}

			for _, expected := range tt.sources {
				found := false
				for _, source := range info.Sources {
					if strings.Contains(source, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected source %q not found in %v", expected, info.Sources)
				}
			}
		})
	}
}

func TestEvaluateWithTaint(t *testing.T) {
	eval := NewEvaluator()

	// Test expression with tainted reference
	result, taintInfo, err := eval.EvaluateWithTaint("${{ github.event.comment.body }}")
	if err != nil {
		t.Fatalf("EvaluateWithTaint() error = %v", err)
	}

	if taintInfo == nil {
		t.Fatal("EvaluateWithTaint() returned nil taintInfo")
	}

	if !taintInfo.IsTainted {
		t.Error("Expected tainted expression")
	}

	_ = result // Result is false for empty context, but we care about taint info
}
