package base

import "github.com/praetorian-inc/trajan/pkg/detections"

// BaseDetection provides common functionality for all detections
type BaseDetection struct {
	name     string
	platform string
	severity detections.Severity
}

// NewBaseDetection creates a new base detection
func NewBaseDetection(name, platform string, severity detections.Severity) BaseDetection {
	return BaseDetection{
		name:     name,
		platform: platform,
		severity: severity,
	}
}

func (d BaseDetection) Name() string                  { return d.name }
func (d BaseDetection) Platform() string              { return d.platform }
func (d BaseDetection) Severity() detections.Severity { return d.severity }
