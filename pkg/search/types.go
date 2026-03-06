// pkg/search/types.go
package search

import "context"

// SearchResult contains repositories matching a search query
type SearchResult struct {
	// Repositories found by the search
	Repositories []string

	// TotalCount is the total number of matches (may exceed Repositories length)
	TotalCount int

	// Incomplete indicates if results were truncated
	Incomplete bool
}

// SearchProvider defines the interface for code search providers
type SearchProvider interface {
	// Search executes a code search and returns matching repositories
	Search(ctx context.Context, query string) (*SearchResult, error)

	// Name returns the provider name (e.g., "github", "sourcegraph")
	Name() string
}

// SearchOptions configures search behavior
type SearchOptions struct {
	// Organization to limit search scope
	Organization string

	// CustomQuery overrides the default self-hosted runner query
	CustomQuery string

	// MaxResults limits the number of results (0 = no limit)
	MaxResults int
}

// DefaultSelfHostedQuery returns the default query for finding self-hosted runners
func DefaultSelfHostedQuery(org string) string {
	if org != "" {
		return "self-hosted org:" + org + " language:yaml path:.github/workflows"
	}
	return "self-hosted language:yaml path:.github/workflows"
}
