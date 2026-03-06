// Package detections provides the detection interface for CI/CD vulnerability detection
package detections

import (
	"context"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// Detection detects specific vulnerability types in workflow graphs
type Detection interface {
	Name() string
	Platform() string
	Severity() Severity
	Detect(ctx context.Context, g *graph.Graph) ([]Finding, error)
}

// DetectionFactory creates new detection instances
type DetectionFactory func() Detection
