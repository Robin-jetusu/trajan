package common

import (
	"regexp"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// InjectableContexts are user-controllable BitBucket predefined variables.
// Note: Bitbucket Pipelines does NOT expose PR title/description or commit
// messages as predefined env vars (unlike GitHub/GitLab). Only branch/tag
// names are available as predefined variables.
var InjectableContexts = []string{
	"BITBUCKET_BRANCH",             // Branch name (user-controlled)
	"BITBUCKET_TAG",                // Tag name (user-controlled)
	"BITBUCKET_DESTINATION_BRANCH", // PR destination branch
}

// ZeroClickTriggers are events that external attackers can trigger
var ZeroClickTriggers = map[graph.Tag]bool{
	graph.TagPullRequest: true,
	// Note: Custom pipelines don't have a specific tag yet
}

// DangerousVariables expose sensitive access.
// BITBUCKET_STEP_OIDC_TOKEN is the only auto-provided sensitive credential.
// The others are conventional names for manually-configured repository
// variables — not predefined, but commonly used by teams.
var DangerousVariables = []string{
	"BITBUCKET_STEP_OIDC_TOKEN",   // Real predefined: OIDC token (when oidc: true)
	"BITBUCKET_ACCESS_TOKEN",      // Conventional: repo/project access token
	"BITBUCKET_BEARER_TOKEN",      // Conventional: bearer token
	"BITBUCKET_APP_PASSWORD",      // Conventional: app password
	"BITBUCKET_REPO_ACCESS_TOKEN", // Conventional: repo access token
}

// VariableExpressionRegex matches BitBucket $VARIABLE and ${VARIABLE} patterns
var VariableExpressionRegex = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)
