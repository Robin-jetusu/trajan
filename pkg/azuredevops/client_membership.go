package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// AddMembership adds a user/group to a group
// API: PUT https://vssps.dev.azure.com/{org}/_apis/graph/memberships/{subjectDescriptor}/{containerDescriptor}?api-version=7.1-preview.1
func (c *Client) AddMembership(ctx context.Context, memberDescriptor, containerDescriptor string) error {
	vssps := c.VSSPSClient()
	encodedMember := url.PathEscape(memberDescriptor)
	encodedContainer := url.PathEscape(containerDescriptor)
	path := fmt.Sprintf("/_apis/graph/memberships/%s/%s?api-version=%s",
		encodedMember, encodedContainer, APIVersionPreview)

	if err := vssps.putJSON(ctx, path, nil, nil); err != nil {
		return fmt.Errorf("adding membership: %w", err)
	}
	return nil
}

// RemoveMembership removes a user/group from a group
// API: DELETE https://vssps.dev.azure.com/{org}/_apis/graph/memberships/{subjectDescriptor}/{containerDescriptor}?api-version=7.1-preview.1
func (c *Client) RemoveMembership(ctx context.Context, memberDescriptor, containerDescriptor string) error {
	vssps := c.VSSPSClient()
	encodedMember := url.PathEscape(memberDescriptor)
	encodedContainer := url.PathEscape(containerDescriptor)
	path := fmt.Sprintf("/_apis/graph/memberships/%s/%s?api-version=%s",
		encodedMember, encodedContainer, APIVersionPreview)

	if err := vssps.deleteRequest(ctx, path); err != nil {
		return fmt.Errorf("removing membership: %w", err)
	}
	return nil
}
