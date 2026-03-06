// pkg/search/github.go
package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultGitHubBaseURL = "https://api.github.com"
)

// GitHubSearchProvider implements SearchProvider using GitHub Code Search API
type GitHubSearchProvider struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// NewGitHubSearchProvider creates a new GitHub search provider
func NewGitHubSearchProvider(client *http.Client, token string) *GitHubSearchProvider {
	return &GitHubSearchProvider{
		httpClient: client,
		token:      token,
		baseURL:    DefaultGitHubBaseURL,
	}
}

// Name returns "github"
func (p *GitHubSearchProvider) Name() string {
	return "github"
}

// Search implements SearchProvider.Search using GitHub Code Search API
func (p *GitHubSearchProvider) Search(ctx context.Context, query string) (*SearchResult, error) {
	result := &SearchResult{
		Repositories: make([]string, 0),
	}

	seen := make(map[string]bool)
	page := 1

	for {
		searchURL := fmt.Sprintf("%s/search/code?q=%s&sort=indexed&per_page=100&page=%d",
			p.baseURL, url.QueryEscape(query), page)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
		if err != nil {
			return result, fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+p.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := p.httpClient.Do(req)
		if err != nil {
			return result, fmt.Errorf("executing request: %w", err)
		}
		defer resp.Body.Close()

		// Handle rate limiting
		if resp.StatusCode == http.StatusForbidden {
			retryAfter := resp.Header.Get("Retry-After")
			reset := resp.Header.Get("X-RateLimit-Reset")

			var sleepDuration time.Duration
			if retryAfter != "" {
				seconds, _ := strconv.Atoi(retryAfter)
				sleepDuration = time.Duration(seconds+5) * time.Second
			} else if reset != "" {
				resetTime, _ := strconv.ParseInt(reset, 10, 64)
				sleepDuration = time.Until(time.Unix(resetTime, 0)) + 5*time.Second
			} else {
				sleepDuration = 60 * time.Second
			}

			slog.Debug("rate limited, waiting", "duration", sleepDuration, "reset", reset, "retry_after", retryAfter)

			select {
			case <-time.After(sleepDuration):
				slog.Debug("resuming after rate limit wait")
				continue // Retry
			case <-ctx.Done():
				return result, ctx.Err()
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return result, fmt.Errorf("search failed (%d): %s", resp.StatusCode, body)
		}

		var searchResp struct {
			TotalCount        int  `json:"total_count"`
			IncompleteResults bool `json:"incomplete_results"`
			Items             []struct {
				Repository struct {
					FullName string `json:"full_name"`
				} `json:"repository"`
			} `json:"items"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
			return result, fmt.Errorf("decoding search response: %w", err)
		}

		result.TotalCount = searchResp.TotalCount
		result.Incomplete = searchResp.IncompleteResults

		// Deduplicate repositories
		for _, item := range searchResp.Items {
			if !seen[item.Repository.FullName] {
				seen[item.Repository.FullName] = true
				result.Repositories = append(result.Repositories, item.Repository.FullName)
			}
		}

		// Check for next page via Link header
		linkHeader := resp.Header.Get("Link")
		if !strings.Contains(linkHeader, `rel="next"`) {
			break
		}

		page++

		// Rate limit between pages (prevent hammering API)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return result, ctx.Err()
		}
	}

	return result, nil
}
