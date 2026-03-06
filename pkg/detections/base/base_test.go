package base

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestBaseDetection(t *testing.T) {
	bd := NewBaseDetection("test", "github", detections.SeverityHigh)

	if bd.Name() != "test" {
		t.Errorf("Name() = %q, want %q", bd.Name(), "test")
	}
	if bd.Platform() != "github" {
		t.Errorf("Platform() = %q, want %q", bd.Platform(), "github")
	}
	if bd.Severity() != detections.SeverityHigh {
		t.Errorf("Severity() = %q, want %q", bd.Severity(), detections.SeverityHigh)
	}
}
