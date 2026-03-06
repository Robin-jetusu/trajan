// modules/trajan/pkg/detections/shared/shared_test.go
package shared

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestDetectorInterface(t *testing.T) {
	var _ Detector = (*mockDetector)(nil)
}

type mockDetector struct{}

func (m *mockDetector) Detect(step *graph.StepNode, ctx *DetectionContext) *detections.Finding {
	return nil
}
