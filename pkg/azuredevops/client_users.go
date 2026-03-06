package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// ListUsers lists users via the Graph API (VSSPS endpoint) with pagination
// API: GET https://vssps.dev.azure.com/{org}/_apis/graph/users?api-version=7.1-preview.1
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	vssps := c.VSSPSClient()
	basePath := fmt.Sprintf("/_apis/graph/users?api-version=%s", APIVersionPreview)

	var allUsers []User
	continuationToken := ""
	for {
		path := basePath
		if continuationToken != "" {
			path += "&continuationToken=" + url.QueryEscape(continuationToken)
		}

		var result UserList
		if err := vssps.getJSON(ctx, path, &result); err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}
		allUsers = append(allUsers, result.Value...)
		if result.ContinuationToken == "" {
			break
		}
		continuationToken = result.ContinuationToken
	}
	return allUsers, nil
}

// GetDescriptor resolves a storage key (e.g., project ID) to a Graph API descriptor
// API: GET https://vssps.dev.azure.com/{org}/_apis/graph/descriptors/{storageKey}?api-version=7.1-preview.1
func (c *Client) GetDescriptor(ctx context.Context, storageKey string) (string, error) {
	vssps := c.VSSPSClient()
	path := fmt.Sprintf("/_apis/graph/descriptors/%s?api-version=%s", url.PathEscape(storageKey), APIVersionPreview)

	var result struct {
		Value string `json:"value"`
	}
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return "", fmt.Errorf("getting descriptor: %w", err)
	}
	return result.Value, nil
}

// ListGroups lists groups via the Graph API (VSSPS endpoint) with pagination.
// If scopeDescriptor is non-empty, groups are scoped to that descriptor (e.g., a project).
// API: GET https://vssps.dev.azure.com/{org}/_apis/graph/groups?scopeDescriptor={desc}&api-version=7.1-preview.1
func (c *Client) ListGroups(ctx context.Context, scopeDescriptor ...string) ([]Group, error) {
	vssps := c.VSSPSClient()
	basePath := fmt.Sprintf("/_apis/graph/groups?api-version=%s", APIVersionPreview)
	if len(scopeDescriptor) > 0 && scopeDescriptor[0] != "" {
		basePath += "&scopeDescriptor=" + url.QueryEscape(scopeDescriptor[0])
	}

	var allGroups []Group
	continuationToken := ""
	for {
		path := basePath
		if continuationToken != "" {
			path += "&continuationToken=" + url.QueryEscape(continuationToken)
		}

		var result GroupList
		if err := vssps.getJSON(ctx, path, &result); err != nil {
			return nil, fmt.Errorf("listing groups: %w", err)
		}
		allGroups = append(allGroups, result.Value...)
		if result.ContinuationToken == "" {
			break
		}
		continuationToken = result.ContinuationToken
	}
	return allGroups, nil
}

// ListGroupMembers lists members of a group by descriptor
// API: GET https://vssps.dev.azure.com/{org}/_apis/graph/memberships/{descriptor}?direction=down&api-version=7.1-preview.1
func (c *Client) ListGroupMembers(ctx context.Context, groupDescriptor string) ([]Membership, error) {
	vssps := c.VSSPSClient()
	encodedDesc := url.PathEscape(groupDescriptor)
	path := fmt.Sprintf("/_apis/graph/memberships/%s?direction=down&api-version=%s", encodedDesc, APIVersionPreview)

	var result MembershipList
	if err := vssps.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing group members: %w", err)
	}
	return result.Value, nil
}

// ListTeams lists all teams in a project with pagination
// API: GET https://dev.azure.com/{org}/_apis/projects/{project}/teams?api-version=7.1-preview.1
func (c *Client) ListTeams(ctx context.Context, projectNameOrID string) ([]Team, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	basePath := fmt.Sprintf("/_apis/projects/%s/teams?api-version=%s", encodedProject, APIVersionPreview)

	var allTeams []Team
	continuationToken := ""
	for {
		path := basePath
		if continuationToken != "" {
			path += "&continuationToken=" + url.QueryEscape(continuationToken)
		}

		var result TeamList
		if err := c.getJSON(ctx, path, &result); err != nil {
			return nil, fmt.Errorf("listing teams: %w", err)
		}
		allTeams = append(allTeams, result.Value...)
		if result.ContinuationToken == "" {
			break
		}
		continuationToken = result.ContinuationToken
	}
	return allTeams, nil
}

// ListTeamMembers lists members of a team
// API: GET https://dev.azure.com/{org}/_apis/projects/{project}/teams/{team}/members?api-version=7.1-preview.1
func (c *Client) ListTeamMembers(ctx context.Context, projectNameOrID, teamID string) ([]TeamMember, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedTeam := url.PathEscape(teamID)
	path := fmt.Sprintf("/_apis/projects/%s/teams/%s/members?api-version=%s", encodedProject, encodedTeam, APIVersionPreview)

	var result TeamMemberList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing team members: %w", err)
	}
	return result.Value, nil
}
