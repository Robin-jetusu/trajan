// pkg/search/types_test.go
package search

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test SearchResult structure
func TestSearchResult(t *testing.T) {
	result := &SearchResult{
		Repositories: []string{"owner/repo1", "owner/repo2"},
		TotalCount:   2,
		Incomplete:   false,
	}

	assert.Len(t, result.Repositories, 2)
	assert.Equal(t, 2, result.TotalCount)
	assert.False(t, result.Incomplete)
}

// Test SearchResult with empty repositories
func TestSearchResult_Empty(t *testing.T) {
	result := &SearchResult{
		Repositories: []string{},
		TotalCount:   0,
		Incomplete:   false,
	}

	assert.Empty(t, result.Repositories)
	assert.Equal(t, 0, result.TotalCount)
}

// Test SearchResult with incomplete flag
func TestSearchResult_Incomplete(t *testing.T) {
	result := &SearchResult{
		Repositories: []string{"owner/repo1"},
		TotalCount:   100,
		Incomplete:   true,
	}

	assert.Len(t, result.Repositories, 1)
	assert.Equal(t, 100, result.TotalCount)
	assert.True(t, result.Incomplete)
}

// Test DefaultSelfHostedQuery with organization
func TestDefaultSelfHostedQuery_WithOrg(t *testing.T) {
	query := DefaultSelfHostedQuery("myorg")

	assert.Contains(t, query, "self-hosted")
	assert.Contains(t, query, "org:myorg")
	assert.Contains(t, query, "language:yaml")
	assert.Contains(t, query, "path:.github/workflows")
}

// Test DefaultSelfHostedQuery without organization
func TestDefaultSelfHostedQuery_WithoutOrg(t *testing.T) {
	query := DefaultSelfHostedQuery("")

	assert.Contains(t, query, "self-hosted")
	assert.NotContains(t, query, "org:")
	assert.Contains(t, query, "language:yaml")
	assert.Contains(t, query, "path:.github/workflows")
}

// Test SearchOptions structure
func TestSearchOptions(t *testing.T) {
	opts := SearchOptions{
		Organization: "myorg",
		CustomQuery:  "self-hosted linux",
		MaxResults:   100,
	}

	assert.Equal(t, "myorg", opts.Organization)
	assert.Equal(t, "self-hosted linux", opts.CustomQuery)
	assert.Equal(t, 100, opts.MaxResults)
}

// Test SearchOptions with zero values
func TestSearchOptions_Defaults(t *testing.T) {
	opts := SearchOptions{}

	assert.Empty(t, opts.Organization)
	assert.Empty(t, opts.CustomQuery)
	assert.Equal(t, 0, opts.MaxResults)
}

// MockSearchProvider implements SearchProvider for testing
type MockSearchProvider struct {
	name   string
	result *SearchResult
	err    error
}

func (m *MockSearchProvider) Search(ctx context.Context, query string) (*SearchResult, error) {
	return m.result, m.err
}

func (m *MockSearchProvider) Name() string {
	return m.name
}

// Test SearchProvider interface with mock
func TestSearchProvider_Interface(t *testing.T) {
	mock := &MockSearchProvider{
		name: "mock",
		result: &SearchResult{
			Repositories: []string{"test/repo"},
			TotalCount:   1,
		},
	}

	assert.Equal(t, "mock", mock.Name())

	result, err := mock.Search(context.Background(), "test query")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Repositories, 1)
}

// Test SearchProvider with error
func TestSearchProvider_Error(t *testing.T) {
	mock := &MockSearchProvider{
		name: "mock",
		err:  assert.AnError,
	}

	result, err := mock.Search(context.Background(), "test query")
	assert.Error(t, err)
	assert.Nil(t, result)
}
