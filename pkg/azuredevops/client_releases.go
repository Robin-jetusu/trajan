package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// ListReleaseDefinitions lists release definitions in a project
// API: GET https://vsrm.dev.azure.com/{org}/{project}/_apis/release/definitions?api-version=7.1-preview.1
func (c *Client) ListReleaseDefinitions(ctx context.Context, projectNameOrID string) ([]ReleaseDefinition, error) {
	vsrm := c.VSRMClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/release/definitions?api-version=%s", encodedProject, APIVersion)

	var result ReleaseDefinitionList
	if err := vsrm.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing release definitions: %w", err)
	}
	return result.Value, nil
}

// GetReleaseDefinition gets a specific release definition by ID
// API: GET https://vsrm.dev.azure.com/{org}/{project}/_apis/release/definitions/{id}?api-version=7.1-preview.1
func (c *Client) GetReleaseDefinition(ctx context.Context, projectNameOrID string, definitionID int) (*ReleaseDefinition, error) {
	vsrm := c.VSRMClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/release/definitions/%d?api-version=%s", encodedProject, definitionID, APIVersion)

	var result ReleaseDefinition
	if err := vsrm.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting release definition: %w", err)
	}
	return &result, nil
}

// ListDeployments lists deployments in a project
// API: GET https://vsrm.dev.azure.com/{org}/{project}/_apis/release/deployments?api-version=7.1-preview.1
func (c *Client) ListDeployments(ctx context.Context, projectNameOrID string) ([]Deployment, error) {
	vsrm := c.VSRMClient()
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/release/deployments?api-version=%s", encodedProject, APIVersion)

	var result DeploymentList
	if err := vsrm.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing deployments: %w", err)
	}
	return result.Value, nil
}
