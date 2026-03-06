package detections

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestDetectionInterface(t *testing.T) {
	// Verify interface exists and has expected methods
	var _ Detection = (*mockDetection)(nil)
}

type mockDetection struct{}

func (m *mockDetection) Name() string       { return "test" }
func (m *mockDetection) Platform() string   { return "github" }
func (m *mockDetection) Severity() Severity { return SeverityHigh }
func (m *mockDetection) Detect(ctx context.Context, g *graph.Graph) ([]Finding, error) {
	return nil, nil
}
