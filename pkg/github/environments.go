package github

import (
	"context"
	"fmt"
)

// Environment represents a deployment environment
type Environment struct {
	Name             string `json:"name"`
	URL              string `json:"url,omitempty"`
	ProtectionRules  int    `json:"protection_rules_count,omitempty"`
	DeploymentBranch string `json:"deployment_branch_policy,omitempty"`
}

// EnvironmentsResponse is the API response for listing environments
type EnvironmentsResponse struct {
	TotalCount   int           `json:"total_count"`
	Environments []Environment `json:"environments"`
}

// ListRepoEnvironments lists deployment environments for a repository
func (c *Client) ListRepoEnvironments(ctx context.Context, owner, repo string) ([]Environment, error) {
	var allEnvs []Environment
	page := 1
	perPage := 100

	for {
		path := fmt.Sprintf("/repos/%s/%s/environments?per_page=%d&page=%d", owner, repo, perPage, page)

		var envsResp EnvironmentsResponse
		if err := c.get(ctx, path, &envsResp); err != nil {
			// Return error - environments endpoint returns 404 if repo has no environments
			return nil, fmt.Errorf("listing environments: %w", err)
		}

		allEnvs = append(allEnvs, envsResp.Environments...)

		if len(envsResp.Environments) < perPage {
			break
		}
		page++
	}

	return allEnvs, nil
}

// ListEnvironmentSecrets lists secrets for a specific environment
func (c *Client) ListEnvironmentSecrets(ctx context.Context, owner, repo, environment string) ([]Secret, error) {
	var allSecrets []Secret
	page := 1
	perPage := 100
	maxRetries := 3

	for {
		path := fmt.Sprintf("/repos/%s/%s/environments/%s/secrets?per_page=%d&page=%d",
			owner, repo, environment, perPage, page)

		var secretsResp SecretsResponse
		if err := c.getWithRetry(ctx, path, &secretsResp, maxRetries); err != nil {
			// Handle permission-denied as empty result
			if apiErr, ok := err.(*APIError); ok && (apiErr.StatusCode == 404 || apiErr.StatusCode == 403) {
				return allSecrets, nil
			}
			return nil, fmt.Errorf("listing environment secrets: %w", err)
		}

		allSecrets = append(allSecrets, secretsResp.Secrets...)

		if len(secretsResp.Secrets) < perPage {
			break
		}
		page++
	}

	return allSecrets, nil
}
