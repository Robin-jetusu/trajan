package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// CreatePipeline creates a new pipeline from a YAML file
// API: POST {org}/{project}/_apis/pipelines?api-version=7.1-preview.1
func (c *Client) CreatePipeline(ctx context.Context, projectNameOrID string, req CreatePipelineRequest) (*Pipeline, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines?api-version=%s", encodedProject, APIVersion)

	var result Pipeline
	if err := c.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("creating pipeline: %w", err)
	}
	return &result, nil
}

// RunPipeline triggers a pipeline run
// API: POST {org}/{project}/_apis/pipelines/{pipelineId}/runs?api-version=7.1-preview.1
func (c *Client) RunPipeline(ctx context.Context, projectNameOrID string, pipelineID int, req RunPipelineRequest) (*PipelineRun, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/%d/runs?api-version=%s", encodedProject, pipelineID, APIVersion)

	var result PipelineRun
	if err := c.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("running pipeline: %w", err)
	}
	return &result, nil
}

// GetPipelineRun gets a specific pipeline run
// API: GET {org}/{project}/_apis/pipelines/{pipelineId}/runs/{runId}?api-version=7.1-preview.1
func (c *Client) GetPipelineRun(ctx context.Context, projectNameOrID string, pipelineID, runID int) (*PipelineRun, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/%d/runs/%d?api-version=%s", encodedProject, pipelineID, runID, APIVersion)

	var result PipelineRun
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting pipeline run: %w", err)
	}
	return &result, nil
}

// DeletePipeline deletes a pipeline (build definition)
// API: DELETE {org}/{project}/_apis/build/definitions/{definitionId}?api-version=7.1-preview.1
func (c *Client) DeletePipeline(ctx context.Context, projectNameOrID string, definitionID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/definitions/%d?api-version=%s", encodedProject, definitionID, APIVersion)

	if err := c.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("deleting pipeline: %w", err)
	}
	return nil
}

// DeleteBuild deletes a build (pipeline run) by its build ID
// API: DELETE {org}/{project}/_apis/build/builds/{buildId}?api-version=7.1-preview.1
func (c *Client) DeleteBuild(ctx context.Context, projectNameOrID string, buildID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/builds/%d?api-version=%s", encodedProject, buildID, APIVersion)

	if err := c.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("deleting build: %w", err)
	}
	return nil
}

// ListPipelinePermissions lists pipeline permissions for a resource
// API: GET {org}/{project}/_apis/pipelines/pipelinePermissions/{resourceType}/{resourceId}?api-version=7.1-preview.1
func (c *Client) ListPipelinePermissions(ctx context.Context, projectNameOrID, resourceType string, resourceID int) (map[string]interface{}, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/pipelinePermissions/%s/%d?api-version=%s",
		encodedProject, url.PathEscape(resourceType), resourceID, APIVersionPreview)

	var result map[string]interface{}
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing pipeline permissions: %w", err)
	}
	return result, nil
}

// AuthorizePipelineResource authorizes a pipeline to access a resource (like variable groups)
// API: PATCH {org}/{project}/_apis/pipelines/pipelinePermissions/{resourceType}/{resourceId}?api-version=7.1-preview.1
func (c *Client) AuthorizePipelineResource(ctx context.Context, projectNameOrID, resourceType string, resourceID, pipelineID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/pipelinePermissions/%s/%d?api-version=%s",
		encodedProject, url.PathEscape(resourceType), resourceID, APIVersionPreview)

	body := PipelinePermissionRequest{
		Pipelines: []PipelinePermission{
			{
				ID:         pipelineID,
				Authorized: true,
			},
		},
	}

	var result map[string]interface{}
	if err := c.patchJSON(ctx, path, body, &result); err != nil {
		return fmt.Errorf("authorizing pipeline %d for %s %d: %w", pipelineID, resourceType, resourceID, err)
	}
	return nil
}

// AuthorizePipelineResourceStr authorizes a pipeline to access a resource using a string resource ID
// This is needed for resources like secure files and service endpoints that use GUID identifiers instead of integer IDs
// API: PATCH {org}/{project}/_apis/pipelines/pipelinePermissions/{resourceType}/{resourceId}?api-version=7.1-preview.1
func (c *Client) AuthorizePipelineResourceStr(ctx context.Context, projectNameOrID, resourceType, resourceID string, pipelineID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/pipelinePermissions/%s/%s?api-version=%s",
		encodedProject, url.PathEscape(resourceType), url.PathEscape(resourceID), APIVersionPreview)

	body := PipelinePermissionRequest{
		Pipelines: []PipelinePermission{
			{
				ID:         pipelineID,
				Authorized: true,
			},
		},
	}

	var result map[string]interface{}
	if err := c.patchJSON(ctx, path, body, &result); err != nil {
		return fmt.Errorf("authorizing pipeline %d for %s %s: %w", pipelineID, resourceType, resourceID, err)
	}
	return nil
}

// GetPipelineArtifact gets a pipeline artifact with a signed download URL
// This is the correct API for artifacts created by PublishPipelineArtifact@1
// API: GET {org}/{project}/_apis/pipelines/{pipelineId}/runs/{runId}/artifacts?artifactName={name}&$expand=signedContent&api-version=7.1
func (c *Client) GetPipelineArtifact(ctx context.Context, projectNameOrID string, pipelineID, runID int, artifactName string) (*PipelineArtifact, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/%d/runs/%d/artifacts?artifactName=%s&$expand=signedContent&api-version=%s",
		encodedProject, pipelineID, runID, url.QueryEscape(artifactName), APIVersion)

	var result PipelineArtifact
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting pipeline artifact: %w", err)
	}
	return &result, nil
}
