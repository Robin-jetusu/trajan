package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// ListAgents lists agents in a specific pool
// API: GET https://dev.azure.com/{org}/_apis/distributedtask/pools/{poolId}/agents?api-version=7.1-preview.1
func (c *Client) ListAgents(ctx context.Context, poolID int) ([]Agent, error) {
	path := fmt.Sprintf("/_apis/distributedtask/pools/%d/agents?includeCapabilities=true&api-version=%s", poolID, APIVersion)

	var result AgentList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	return result.Value, nil
}

// ListAgentQueues lists agent queues in a project
// API: GET https://dev.azure.com/{org}/{project}/_apis/distributedtask/queues?api-version=7.1-preview.1
func (c *Client) ListAgentQueues(ctx context.Context, projectNameOrID string) ([]AgentQueue, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/distributedtask/queues?api-version=%s", encodedProject, APIVersion)

	var result AgentQueueList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing agent queues: %w", err)
	}
	return result.Value, nil
}

// GetEnvironment gets a single environment with expanded resources
// API: GET https://dev.azure.com/{org}/{project}/_apis/distributedtask/environments/{envId}?expands=resourceReferences&api-version=7.1-preview.1
func (c *Client) GetEnvironment(ctx context.Context, projectNameOrID string, envID int) (*Environment, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/distributedtask/environments/%d?expands=resourceReferences&api-version=%s", encodedProject, envID, APIVersion)

	var result Environment
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting environment: %w", err)
	}
	return &result, nil
}
