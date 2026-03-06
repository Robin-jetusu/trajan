package github

import (
	"context"
	"fmt"
)

// ListOrgActionsVariables lists all Actions variables for an organization
// Returns empty slice (not error) for 404/403
func (c *Client) ListOrgActionsVariables(ctx context.Context, org string) ([]Variable, error) {
	var allVars []Variable
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/orgs/%s/actions/variables?per_page=%d&page=%d", org, perPage, page)

		var varsResp VariablesResponse
		if err := c.getWithRetry(ctx, path, &varsResp, maxRetries); err != nil {
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allVars, nil
			}
			return nil, fmt.Errorf("listing org actions variables: %w", err)
		}

		allVars = append(allVars, varsResp.Variables...)

		if len(varsResp.Variables) < perPage {
			break
		}
		page++
	}

	return allVars, nil
}

// ListRepoActionsVariables lists all Actions variables for a repository
// Returns empty slice (not error) for 404/403
func (c *Client) ListRepoActionsVariables(ctx context.Context, owner, repo string) ([]Variable, error) {
	var allVars []Variable
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/repos/%s/%s/actions/variables?per_page=%d&page=%d", owner, repo, perPage, page)

		var varsResp VariablesResponse
		if err := c.getWithRetry(ctx, path, &varsResp, maxRetries); err != nil {
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allVars, nil
			}
			return nil, fmt.Errorf("listing repo actions variables: %w", err)
		}

		allVars = append(allVars, varsResp.Variables...)

		if len(varsResp.Variables) < perPage {
			break
		}
		page++
	}

	return allVars, nil
}
