package common

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// ParseOwnerRepo extracts owner and repo from target
// Accepts both "owner/repo" and "https://github.com/owner/repo" formats
func ParseOwnerRepo(target platforms.Target) (owner, repo string, err error) {
	// Strip GitHub URL prefix if present
	targetValue := target.Value
	targetValue = strings.TrimPrefix(targetValue, "https://github.com/")
	targetValue = strings.TrimPrefix(targetValue, "http://github.com/")
	targetValue = strings.TrimSuffix(targetValue, "/")

	parts := strings.Split(targetValue, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repo format (expected owner/repo or https://github.com/owner/repo)")
	}
	return parts[0], parts[1], nil
}

// ParseRepoString extracts owner and repo from an "owner/repo" string.
// Unlike ParseOwnerRepo, this takes a plain string rather than a Target.
func ParseRepoString(repoSlug string) (owner, repo string, err error) {
	repoSlug = strings.TrimPrefix(repoSlug, "https://github.com/")
	repoSlug = strings.TrimPrefix(repoSlug, "http://github.com/")
	repoSlug = strings.TrimSuffix(repoSlug, "/")

	parts := strings.Split(repoSlug, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repo format (expected owner/repo or https://github.com/owner/repo)")
	}
	return parts[0], parts[1], nil
}
