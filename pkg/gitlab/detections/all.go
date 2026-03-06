// Package gitlab registers all GitLab CI detections
package detections

import (
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/ai"               // AI risk detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/includes"         // Include injection detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/injection"        // Script injection detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/mrcheckout"       // Merge request unsafe checkout detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/mrsecrets"        // Merge request secrets exposure detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/permissions"      // Token exposure detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/selfhostedrunner" // Self-hosted runner exposure detection
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/unpinned"         // Unpinned include detection
)
