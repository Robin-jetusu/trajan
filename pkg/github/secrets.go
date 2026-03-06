package github

import (
	"context"
	"fmt"
)

// ListOrgActionsSecrets lists all Actions secrets for an organization
// Requires: PAT with admin:org scope, or GitHub App with organization_self_hosted_runners permission
// Returns empty slice (not error) for 404/403 - treats as "no access or no resources"
func (c *Client) ListOrgActionsSecrets(ctx context.Context, org string) ([]Secret, error) {
	var allSecrets []Secret
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/orgs/%s/actions/secrets?per_page=%d&page=%d", org, perPage, page)

		var secretsResp SecretsResponse
		if err := c.getWithRetry(ctx, path, &secretsResp, maxRetries); err != nil {
			// Handle permission-denied as empty result (GitHub design pattern)
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allSecrets, nil
			}
			return nil, fmt.Errorf("listing org actions secrets: %w", err)
		}

		allSecrets = append(allSecrets, secretsResp.Secrets...)

		// Stop if we got fewer than requested (last page)
		if len(secretsResp.Secrets) < perPage {
			break
		}
		page++
	}

	return allSecrets, nil
}

// ListRepoOrgSecrets lists organization secrets inherited by a repository
// Requires: PAT with repo scope
// Returns empty slice (not error) for 404/403
func (c *Client) ListRepoOrgSecrets(ctx context.Context, owner, repo string) ([]Secret, error) {
	var allSecrets []Secret
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/repos/%s/%s/actions/organization-secrets?per_page=%d&page=%d", owner, repo, perPage, page)

		var secretsResp SecretsResponse
		if err := c.getWithRetry(ctx, path, &secretsResp, maxRetries); err != nil {
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allSecrets, nil
			}
			return nil, fmt.Errorf("listing repo org secrets: %w", err)
		}

		allSecrets = append(allSecrets, secretsResp.Secrets...)

		if len(secretsResp.Secrets) < perPage {
			break
		}
		page++
	}

	return allSecrets, nil
}

// ListRepoActionsSecrets lists all Actions secrets for a repository
// Requires: PAT with repo scope, or GitHub App with secrets permission (read)
// Returns empty slice (not error) for 404/403 - treats as "no access or no resources"
func (c *Client) ListRepoActionsSecrets(ctx context.Context, owner, repo string) ([]Secret, error) {
	var allSecrets []Secret
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/repos/%s/%s/actions/secrets?per_page=%d&page=%d", owner, repo, perPage, page)

		var secretsResp SecretsResponse
		if err := c.getWithRetry(ctx, path, &secretsResp, maxRetries); err != nil {
			// Handle permission-denied as empty result
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allSecrets, nil
			}
			return nil, fmt.Errorf("listing repo actions secrets: %w", err)
		}

		allSecrets = append(allSecrets, secretsResp.Secrets...)

		if len(secretsResp.Secrets) < perPage {
			break
		}
		page++
	}

	return allSecrets, nil
}
