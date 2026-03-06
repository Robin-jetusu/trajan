package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

var (
	detectionMu       sync.RWMutex
	detectionRegistry = make(map[string][]detections.DetectionFactory)
	detectionIDs      = make(map[string]bool)
)

// RegisterDetection registers a detection factory for a platform
func RegisterDetection(platform, name string, factory detections.DetectionFactory) {
	detectionMu.Lock()
	defer detectionMu.Unlock()

	id := platform + "/" + name
	if detectionIDs[id] {
		panic(fmt.Sprintf("detection: Register called twice for %s", id))
	}
	detectionIDs[id] = true

	detectionRegistry[platform] = append(detectionRegistry[platform], factory)
}

// GetDetections returns new instances of all detections for a platform
func GetDetections(platform string) []detections.Detection {
	detectionMu.RLock()
	defer detectionMu.RUnlock()
	factories := detectionRegistry[platform]
	result := make([]detections.Detection, 0, len(factories))
	for _, factory := range factories {
		result = append(result, factory())
	}
	return result
}

// GetDetectionsForPlatform returns detections for a specific platform plus "all" (cross-platform)
func GetDetectionsForPlatform(platform string) []detections.Detection {
	detectionMu.RLock()
	defer detectionMu.RUnlock()

	// Get platform-specific detections
	platformDets := make([]detections.Detection, 0)
	for _, factory := range detectionRegistry[platform] {
		platformDets = append(platformDets, factory())
	}

	// Add cross-platform detections
	for _, factory := range detectionRegistry["all"] {
		platformDets = append(platformDets, factory())
	}

	return platformDets
}

// ListDetectionPlatforms returns all platforms with registered detections
func ListDetectionPlatforms() []string {
	detectionMu.RLock()
	defer detectionMu.RUnlock()
	names := make([]string, 0, len(detectionRegistry))
	for name := range detectionRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResetDetections clears the detection registry (for testing)
func ResetDetections() {
	detectionMu.Lock()
	defer detectionMu.Unlock()
	detectionRegistry = make(map[string][]detections.DetectionFactory)
	detectionIDs = make(map[string]bool)
}
