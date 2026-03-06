package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// ListBuilds lists recent builds in a project
// API: GET {org}/{project}/_apis/build/builds?api-version=7.1-preview.1
func (c *Client) ListBuilds(ctx context.Context, projectNameOrID string) ([]Build, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds?api-version=%s", encodedProject, APIVersion)

	var result BuildList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing builds: %w", err)
	}
	return result.Value, nil
}

// ListBuildDefinitions lists build definitions (pipeline definitions) in a project
// API: GET {org}/{project}/_apis/build/definitions?api-version=7.1-preview.1
func (c *Client) ListBuildDefinitions(ctx context.Context, projectNameOrID string) ([]BuildDefinition, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/definitions?$expand=process&api-version=%s", encodedProject, APIVersion)

	var result BuildDefinitionList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing build definitions: %w", err)
	}
	return result.Value, nil
}

// ListBuildDefinitionsByRepo lists build definitions for a specific repository.
// Uses repositoryId + repositoryType filters to scope results to one repo.
// NOTE: The list response omits process.yamlFilename and repository.name —
// callers must use GetBuildDefinition to retrieve the full definition.
// API: GET {org}/{project}/_apis/build/definitions?repositoryId={id}&repositoryType=TfsGit&api-version=7.1
func (c *Client) ListBuildDefinitionsByRepo(ctx context.Context, projectNameOrID, repositoryID string) ([]BuildDefinition, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/definitions?repositoryId=%s&repositoryType=TfsGit&api-version=%s",
		encodedProject, url.QueryEscape(repositoryID), APIVersion)

	var result BuildDefinitionList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing build definitions for repo %s: %w", repositoryID, err)
	}
	return result.Value, nil
}

// GetBuildDefinition gets a specific build definition by ID
// API: GET {org}/{project}/_apis/build/definitions/{id}?api-version=7.1-preview.1
func (c *Client) GetBuildDefinition(ctx context.Context, projectNameOrID string, definitionID int) (*BuildDefinition, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/definitions/%d?api-version=%s", encodedProject, definitionID, APIVersion)

	var result BuildDefinition
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting build definition: %w", err)
	}
	return &result, nil
}

// GetBuildTimeline gets the timeline (steps/tasks) for a build
// API: GET {org}/{project}/_apis/build/builds/{buildId}/timeline?api-version=7.1-preview.1
func (c *Client) GetBuildTimeline(ctx context.Context, projectNameOrID string, buildID int) (*BuildTimeline, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds/%d/timeline?api-version=%s", encodedProject, buildID, APIVersion)

	var result BuildTimeline
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting build timeline: %w", err)
	}
	return &result, nil
}

// ListBuildLogs lists all logs for a build
// API: GET {org}/{project}/_apis/build/builds/{buildId}/logs?api-version=7.1-preview.1
func (c *Client) ListBuildLogs(ctx context.Context, projectNameOrID string, buildID int) ([]BuildLog, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds/%d/logs?api-version=%s", encodedProject, buildID, APIVersion)

	var result BuildLogList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing build logs: %w", err)
	}
	return result.Value, nil
}

// GetBuildLog gets a specific log from a build
// API: GET {org}/{project}/_apis/build/builds/{buildId}/logs/{logId}?api-version=7.1-preview.1
func (c *Client) GetBuildLog(ctx context.Context, projectNameOrID string, buildID, logID int) ([]byte, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds/%d/logs/%d?api-version=%s", encodedProject, buildID, logID, APIVersion)

	return c.getRaw(ctx, path)
}

// QueueBuild queues a new build for a definition
// API: POST {org}/{project}/_apis/build/builds?api-version=7.1-preview.1
func (c *Client) QueueBuild(ctx context.Context, projectNameOrID string, definitionID int, sourceBranch string) (*Build, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds?api-version=%s", encodedProject, APIVersion)

	body := map[string]interface{}{
		"definition":   map[string]int{"id": definitionID},
		"sourceBranch": sourceBranch,
	}

	var result Build
	if err := c.postJSON(ctx, path, body, &result); err != nil {
		return nil, fmt.Errorf("queuing build: %w", err)
	}
	return &result, nil
}

// GetBuild gets a specific build by ID
// API: GET {org}/{project}/_apis/build/builds/{buildId}?api-version=7.1-preview.1
func (c *Client) GetBuild(ctx context.Context, projectNameOrID string, buildID int) (*Build, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds/%d?api-version=%s", encodedProject, buildID, APIVersion)

	var result Build
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting build: %w", err)
	}
	return &result, nil
}
