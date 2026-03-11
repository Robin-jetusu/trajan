package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// calleeResult caches the resolution of a reusable workflow callee.
type calleeResult struct {
	isSelfHosted bool
	runsOn       string
	err          error
}

// reusableWorkflowResolver resolves the runs-on of reusable workflow callees.
// It checks local workflows (all_workflows metadata) first, then falls back to
// the GitHub API for cross-repo references.
type reusableWorkflowResolver struct {
	client       *github.Client
	allWorkflows map[string][]platforms.Workflow
	cache        map[string]*calleeResult
	mu           sync.Mutex
}

func newResolver(client *github.Client, allWorkflows map[string][]platforms.Workflow) *reusableWorkflowResolver {
	return &reusableWorkflowResolver{
		client:       client,
		allWorkflows: allWorkflows,
		cache:        make(map[string]*calleeResult),
	}
}

// resolveCallee determines whether a reusable workflow callee uses self-hosted runners.
// usesRef is the job-level `uses:` value, e.g. "org/repo/.github/workflows/build.yml@main"
// or "./.github/workflows/build.yml".
// callerRepoSlug is "owner/repo" of the calling workflow.
func (r *reusableWorkflowResolver) resolveCallee(ctx context.Context, callerRepoSlug, usesRef string) (isSelfHosted bool, runsOn string, err error) {
	r.mu.Lock()
	if cached, ok := r.cache[usesRef]; ok {
		r.mu.Unlock()
		return cached.isSelfHosted, cached.runsOn, cached.err
	}
	r.mu.Unlock()

	isSelfHosted, runsOn, err = r.doResolve(ctx, callerRepoSlug, usesRef)

	r.mu.Lock()
	r.cache[usesRef] = &calleeResult{isSelfHosted: isSelfHosted, runsOn: runsOn, err: err}
	r.mu.Unlock()

	return isSelfHosted, runsOn, err
}

func (r *reusableWorkflowResolver) doResolve(ctx context.Context, callerRepoSlug, usesRef string) (bool, string, error) {
	// Local reference: ./.github/workflows/build.yml
	if strings.HasPrefix(usesRef, "./") {
		return r.resolveLocal(callerRepoSlug, usesRef)
	}

	// Cross-repo reference: owner/repo/.github/workflows/build.yml@ref
	return r.resolveCrossRepo(ctx, callerRepoSlug, usesRef)
}

// resolveLocal resolves a local reusable workflow reference against all_workflows metadata.
func (r *reusableWorkflowResolver) resolveLocal(callerRepoSlug, usesRef string) (bool, string, error) {
	// Strip leading "./"
	localPath := strings.TrimPrefix(usesRef, "./")

	if r.allWorkflows == nil {
		return false, "", fmt.Errorf("no all_workflows metadata available")
	}

	// Look through all workflows for the caller's repo
	repoWorkflows, ok := r.allWorkflows[callerRepoSlug]
	if !ok {
		return false, "", fmt.Errorf("repo %s not found in all_workflows", callerRepoSlug)
	}

	for _, wf := range repoWorkflows {
		if wf.Path == localPath || strings.HasSuffix(wf.Path, "/"+localPath) {
			return r.parseCalleeContent(wf.Content)
		}
	}

	return false, "", fmt.Errorf("local workflow %s not found in all_workflows for %s", localPath, callerRepoSlug)
}

// resolveCrossRepo resolves a cross-repo reusable workflow reference.
// Format: owner/repo/path@ref
func (r *reusableWorkflowResolver) resolveCrossRepo(ctx context.Context, callerRepoSlug, usesRef string) (bool, string, error) {
	owner, repo, path, ref, err := parseCrossRepoRef(usesRef)
	if err != nil {
		return false, "", err
	}

	repoSlug := owner + "/" + repo

	// Check all_workflows first (callee may already be in scope)
	if r.allWorkflows != nil {
		if repoWorkflows, ok := r.allWorkflows[repoSlug]; ok {
			for _, wf := range repoWorkflows {
				if wf.Path == path || strings.HasSuffix(wf.Path, "/"+path) {
					return r.parseCalleeContent(wf.Content)
				}
			}
		}
	}

	// Fall back to API
	if r.client == nil {
		return false, "", fmt.Errorf("no github client available for cross-repo resolution")
	}

	content, err := r.client.GetWorkflowContentAtRef(ctx, owner, repo, path, ref)
	if err != nil {
		return false, "", fmt.Errorf("fetching cross-repo workflow %s: %w", usesRef, err)
	}

	return r.parseCalleeContent(content)
}

// parseCalleeContent parses workflow YAML and checks if any job uses a self-hosted runner.
func (r *reusableWorkflowResolver) parseCalleeContent(content []byte) (bool, string, error) {
	p := parser.NewGitHubParser()
	wf, err := p.Parse(content)
	if err != nil {
		return false, "", fmt.Errorf("parsing callee workflow: %w", err)
	}

	for _, job := range wf.Jobs {
		if job.SelfHosted {
			return true, job.RunsOn, nil
		}
	}

	return false, "", nil
}

// parseCrossRepoRef parses "owner/repo/path/to/workflow.yml@ref" into components.
func parseCrossRepoRef(usesRef string) (owner, repo, path, ref string, err error) {
	// Split on @
	parts := strings.SplitN(usesRef, "@", 2)
	if len(parts) != 2 {
		return "", "", "", "", fmt.Errorf("invalid reusable workflow reference (no @ref): %s", usesRef)
	}
	ref = parts[1]

	// Split path: owner/repo/remaining/path
	pathParts := strings.SplitN(parts[0], "/", 3)
	if len(pathParts) < 3 {
		return "", "", "", "", fmt.Errorf("invalid reusable workflow reference (need owner/repo/path): %s", usesRef)
	}

	owner = pathParts[0]
	repo = pathParts[1]
	path = pathParts[2]

	return owner, repo, path, ref, nil
}
