package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// ListPolicyConfigurations lists branch policies in a project
// API: GET {org}/{project}/_apis/policy/configurations?api-version=7.1-preview.1
func (c *Client) ListPolicyConfigurations(ctx context.Context, projectNameOrID string) ([]PolicyConfiguration, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/policy/configurations?api-version=%s", encodedProject, APIVersion)

	var result PolicyConfigurationList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing policy configurations: %w", err)
	}
	return result.Value, nil
}

// ListSecureFiles lists secure files in a project
// API: GET {org}/{project}/_apis/distributedtask/securefiles?api-version=7.1-preview.1
func (c *Client) ListSecureFiles(ctx context.Context, projectNameOrID string) ([]SecureFile, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/distributedtask/securefiles?api-version=%s", encodedProject, APIVersionPreview)

	var result SecureFileList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing secure files: %w", err)
	}
	return result.Value, nil
}

// ListEnvironments lists environments in a project
// API: GET {org}/{project}/_apis/pipelines/environments?api-version=7.1-preview.1
func (c *Client) ListEnvironments(ctx context.Context, projectNameOrID string) ([]Environment, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/environments?api-version=%s", encodedProject, APIVersion)

	var result EnvironmentList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing environments: %w", err)
	}
	return result.Value, nil
}

// ListCheckConfigurations lists pipeline check configurations for a resource
// API: GET {org}/{project}/_apis/pipelines/checks/configurations?resourceType={type}&resourceId={id}&$expand=settings&api-version=7.1-preview.1
func (c *Client) ListCheckConfigurations(ctx context.Context, projectNameOrID, resourceType, resourceID string) ([]CheckConfiguration, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/checks/configurations?resourceType=%s&resourceId=%s&$expand=settings&api-version=%s",
		encodedProject, url.QueryEscape(resourceType), url.QueryEscape(resourceID), APIVersion)

	var result CheckConfigurationList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing check configurations: %w", err)
	}
	return result.Value, nil
}

// ListAllCheckConfigurations lists all pipeline check configurations in a project
// API: GET {org}/{project}/_apis/pipelines/checks/configurations?api-version=7.1-preview.1
func (c *Client) ListAllCheckConfigurations(ctx context.Context, projectNameOrID string) ([]CheckConfiguration, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/pipelines/checks/configurations?$expand=settings&api-version=%s", encodedProject, APIVersion)

	var result CheckConfigurationList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing check configurations: %w", err)
	}
	return result.Value, nil
}

// ListPolicyTypes lists policy type definitions in a project
// API: GET {org}/{project}/_apis/policy/types?api-version=7.1-preview.1
func (c *Client) ListPolicyTypes(ctx context.Context, projectNameOrID string) ([]PolicyType, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/policy/types?api-version=%s", encodedProject, APIVersion)

	var result PolicyTypeList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing policy types: %w", err)
	}
	return result.Value, nil
}

// GetBuildGeneralSettings gets project-level build security settings
// API: GET {org}/{project}/_apis/build/generalsettings?api-version=7.1-preview.1
func (c *Client) GetBuildGeneralSettings(ctx context.Context, projectNameOrID string) (*BuildGeneralSettings, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	path := fmt.Sprintf("/%s/_apis/build/generalsettings?api-version=%s", encodedProject, APIVersion)

	var result BuildGeneralSettings
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting build general settings: %w", err)
	}
	return &result, nil
}
