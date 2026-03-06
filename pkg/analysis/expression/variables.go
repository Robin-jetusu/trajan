// pkg/analysis/expression/variables.go
package expression

import "github.com/praetorian-inc/trajan/pkg/detections/shared/taintsources"

// StandardVariables returns the standard GitHub Actions context variables
// with appropriate Value types for security analysis
func StandardVariables() map[string]Value {
	vars := map[string]Value{
		// Flexible action values (can be multiple different strings)
		"github.event.action": NewFlexibleAction([]string{
			"opened", "edited", "synchronize", "reopened", "closed",
			"labeled", "unlabeled", "created", "deleted",
		}),

		// Boolean values with security-relevant defaults
		"github.event.pull_request.head.repo.fork": NewBoolValue(true),  // Assume fork by default (worst case)
		"github.event.pull_request.merged":         NewBoolValue(false), // Not merged by default

		// Safe context values (not user-controllable)
		"github.sha":        NewStringValue("a1b2c3d4"),
		"github.ref":        NewStringValue("refs/heads/main"),
		"github.repository": NewStringValue("owner/repo"),
		"github.actor":      NewStringValue("user"),
	}

	// User-controllable inputs (Wildcards) from canonical list
	for _, ctx := range taintsources.GitHubTaintedContexts {
		vars[ctx] = NewWildcard(ctx)
	}

	return vars
}
