package common

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/trajan/pkg/github"
)

// GetDefaultBranch retrieves the default branch for a repository
func GetDefaultBranch(ctx context.Context, client *github.Client, owner, repo string) (string, error) {
	repository, err := client.GetRepository(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("getting repository: %w", err)
	}

	defaultBranch := repository.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	return defaultBranch, nil
}

// GetBranchSHA retrieves the SHA for a branch
func GetBranchSHA(ctx context.Context, client *github.Client, owner, repo, branch string) (string, error) {
	ref, err := client.GetRef(ctx, owner, repo, "heads/"+branch)
	if err != nil {
		return "", fmt.Errorf("getting branch ref: %w", err)
	}
	return ref.Object.SHA, nil
}

// GetFileSHA retrieves the blob SHA of a file in a repository (needed for deletion via contents API)
func GetFileSHA(ctx context.Context, client *github.Client, owner, repo, path string) (string, error) {
	file, err := client.GetFileMetadata(ctx, owner, repo, path)
	if err != nil {
		return "", fmt.Errorf("getting file metadata: %w", err)
	}
	return file.SHA, nil
}
