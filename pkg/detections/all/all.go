package all

// Import statements ensure init functions run in each detection.
// When a new detection is added, this list should be updated.

import (
	// Azure DevOps detections
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections"

	// GitHub detections - AI (consolidated)
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/ai"

	// GitHub detections - Standard
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/artifact"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/cache"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/injection"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/permissions"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/pwnrequest"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/review"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/runner"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/toctou"
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/unpinned"

	// GitHub detections - Advanced
	_ "github.com/praetorian-inc/trajan/pkg/github/detections/envbypass"

	// GitLab detections
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections"

	// Jenkins detections
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections"
)
