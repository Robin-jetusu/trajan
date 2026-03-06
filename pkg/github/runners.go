package github

import (
	"context"
	"fmt"
)

// ListOrgRunners lists all self-hosted runners for an organization
// Requires: PAT with admin:org + repo (for private repos), or GitHub App with organization_self_hosted_runners permission
// Returns the error on 403/404 so callers can route it to PermissionErrors
func (c *Client) ListOrgRunners(ctx context.Context, org string) ([]Runner, error) {
	var allRunners []Runner
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/orgs/%s/actions/runners?per_page=%d&page=%d", org, perPage, page)

		var runnersResp RunnersResponse
		if err := c.getWithRetry(ctx, path, &runnersResp, maxRetries); err != nil {
			// Return 403/404 errors so caller can decide how to handle
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allRunners, err
			}
			return nil, fmt.Errorf("listing org runners: %w", err)
		}

		allRunners = append(allRunners, runnersResp.Runners...)

		if len(runnersResp.Runners) < perPage {
			break
		}
		page++
	}

	return allRunners, nil
}

// ListRepoRunners lists all self-hosted runners for a repository
// Requires: PAT with repo scope, or GitHub App with administration permission
// Returns the error on 403/404 so callers can route it to PermissionErrors
func (c *Client) ListRepoRunners(ctx context.Context, owner, repo string) ([]Runner, error) {
	var allRunners []Runner
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/repos/%s/%s/actions/runners?per_page=%d&page=%d", owner, repo, perPage, page)

		var runnersResp RunnersResponse
		if err := c.getWithRetry(ctx, path, &runnersResp, maxRetries); err != nil {
			// Return 403/404 errors so caller can decide how to handle
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allRunners, err
			}
			return nil, fmt.Errorf("listing repo runners: %w", err)
		}

		allRunners = append(allRunners, runnersResp.Runners...)

		if len(runnersResp.Runners) < perPage {
			break
		}
		page++
	}

	return allRunners, nil
}

// ListOrgRunnerGroups lists all runner groups for an organization
// Requires: PAT with admin:org scope, or GitHub App with organization_self_hosted_runners permission
// Returns the error on 403/404 so callers can route it to PermissionErrors
func (c *Client) ListOrgRunnerGroups(ctx context.Context, org string) ([]RunnerGroup, error) {
	var allGroups []RunnerGroup
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/orgs/%s/actions/runner-groups?per_page=%d&page=%d", org, perPage, page)

		var groupsResp RunnerGroupsResponse
		if err := c.getWithRetry(ctx, path, &groupsResp, maxRetries); err != nil {
			// Return 403/404 errors so caller can decide how to handle
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allGroups, err
			}
			return nil, fmt.Errorf("listing runner groups: %w", err)
		}

		allGroups = append(allGroups, groupsResp.RunnerGroups...)

		if len(groupsResp.RunnerGroups) < perPage {
			break
		}
		page++
	}

	return allGroups, nil
}
