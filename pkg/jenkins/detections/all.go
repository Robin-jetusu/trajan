// Package jenkins registers all Jenkins CI detections
package detections

import (
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/agents"        // Agent security detection
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/anonymous"     // Anonymous access detection
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/credentials"   // Credential exposure detection
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/csrf"          // CSRF disabled detection
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/injection"     // Script injection detection
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/permissions"   // Permission issues detection
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/detections/scriptconsole" // Script console detection
)
