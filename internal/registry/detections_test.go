package registry

import (
	"testing"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestRegisterDetection(t *testing.T) {
	ResetDetections()

	called := false
	RegisterDetection("github", "test", func() detections.Detection {
		called = true
		return nil
	})

	dets := GetDetections("github")
	if len(dets) != 1 {
		t.Errorf("GetDetections() returned %d detections, want 1", len(dets))
	}
	if !called {
		t.Error("Factory was not called")
	}
}

func TestGetDetectionsForPlatform(t *testing.T) {
	ResetDetections()

	// Register platform-specific detection
	RegisterDetection("github", "github-specific", func() detections.Detection { return nil })

	// Register cross-platform detection
	RegisterDetection("all", "cross-platform", func() detections.Detection { return nil })

	// GetDetectionsForPlatform should return both platform-specific and cross-platform
	dets := GetDetectionsForPlatform("github")
	if len(dets) != 2 {
		t.Errorf("GetDetectionsForPlatform() returned %d, want 2", len(dets))
	}

	// Different platform should also get cross-platform detections
	RegisterDetection("gitlab", "gitlab-specific", func() detections.Detection { return nil })
	dets = GetDetectionsForPlatform("gitlab")
	if len(dets) != 2 {
		t.Errorf("GetDetectionsForPlatform() returned %d, want 2 (gitlab-specific + cross-platform)", len(dets))
	}

	// Platform with no specific detections should still get cross-platform
	dets = GetDetectionsForPlatform("bitbucket")
	if len(dets) != 1 {
		t.Errorf("GetDetectionsForPlatform() returned %d, want 1 (cross-platform only)", len(dets))
	}
}
