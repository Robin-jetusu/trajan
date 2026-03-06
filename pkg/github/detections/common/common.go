package common

import (
	"regexp"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections/shared/taintsources"
)

// InjectableContexts are user-controllable GitHub contexts
var InjectableContexts = taintsources.GitHubTaintedContexts

// ZeroClickTriggers are events that external attackers can trigger
var ZeroClickTriggers = map[graph.Tag]bool{
	graph.TagIssueComment:      true,
	graph.TagPullRequestTarget: true,
	graph.TagPullRequest:       true,
	graph.TagIssues:            true,
	graph.TagDiscussion:        true,
	graph.TagFork:              true,
}

// ExpressionRegex matches GitHub Actions ${{ }} expressions
var ExpressionRegex = regexp.MustCompile(`\$\{\{.+?\}\}`)
