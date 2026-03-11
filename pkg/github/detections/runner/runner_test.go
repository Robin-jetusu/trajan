package runner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestRunnerPlugin_DetectsSelfHosted(t *testing.T) {
	yaml := `
name: Build
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "Running on self-hosted"
`
	g, err := analysis.BuildGraph("owner/repo", "build.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "self-hosted")
}

func TestRunnerPlugin_GitHubHostedIsSafe(t *testing.T) {
	yaml := `
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "GitHub hosted"
`
	g, err := analysis.BuildGraph("owner/repo", "safe.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

func TestRunnerPlugin_Properties(t *testing.T) {
	p := New()
	assert.Equal(t, "self-hosted-runner", p.Name())
	assert.Equal(t, "github", p.Platform())
	assert.Equal(t, detections.SeverityHigh, p.Severity())
}

func TestRunnerPlugin_ReusableWorkflowCallerNoFalsePositive(t *testing.T) {
	// A caller job with uses: and no runs-on should NOT produce a finding
	// when there is no metadata to resolve the callee (fail-open = no finding).
	yaml := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared/.github/workflows/build.yml@main
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "reusable workflow caller with no metadata should produce 0 findings")
}

func TestRunnerPlugin_ReusableWorkflowCallerResolvesToSelfHosted(t *testing.T) {
	// Callee has runs-on: self-hosted → should produce a finding
	callerYAML := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared/.github/workflows/build.yml@main
`
	calleeYAML := `
name: Build
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "build"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	// Set up all_workflows with the callee so the resolver can find it
	allWorkflows := map[string][]platforms.Workflow{
		"org/shared": {
			{
				Name:     "build.yml",
				Path:     ".github/workflows/build.yml",
				Content:  []byte(calleeYAML),
				RepoSlug: "org/shared",
			},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "callee with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_ReusableWorkflowCallerResolvesToGitHubHosted(t *testing.T) {
	// Callee has runs-on: ubuntu-latest → should NOT produce a finding
	callerYAML := `
name: CI
on: push
jobs:
  call-build:
    uses: org/shared/.github/workflows/build.yml@main
`
	calleeYAML := `
name: Build
on: workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		"org/shared": {
			{
				Name:     "build.yml",
				Path:     ".github/workflows/build.yml",
				Content:  []byte(calleeYAML),
				RepoSlug: "org/shared",
			},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "callee with GitHub-hosted runner should produce 0 findings")
}

func TestRunnerPlugin_LocalReusableWorkflowResolution(t *testing.T) {
	// Local reusable workflow caller (./) resolved via all_workflows
	callerYAML := `
name: CI
on: push
jobs:
  call-local:
    uses: ./.github/workflows/reusable-build.yml
`
	calleeYAML := `
name: Reusable Build
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "build"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		"owner/repo": {
			{
				Name:     "reusable-build.yml",
				Path:     ".github/workflows/reusable-build.yml",
				Content:  []byte(calleeYAML),
				RepoSlug: "owner/repo",
			},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "local callee with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_NestedReusableWorkflow_TwoLevels(t *testing.T) {
	// A calls B (cross-repo), B calls C (local to B's repo), C has self-hosted.
	// Tests recursive resolution AND correct slug threading.
	callerYAML := `
name: CI
on: push
jobs:
  call-b:
    uses: org/middle/.github/workflows/b.yml@main
`
	// B is in org/middle and calls C locally
	middleYAML := `
name: Middle
on: workflow_call
jobs:
  call-c:
    uses: ./.github/workflows/c.yml
`
	// C is in org/middle (same repo as B) and uses self-hosted
	leafYAML := `
name: Leaf
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "self-hosted leaf"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		"org/middle": {
			{
				Name:     "b.yml",
				Path:     ".github/workflows/b.yml",
				Content:  []byte(middleYAML),
				RepoSlug: "org/middle",
			},
			{
				Name:     "c.yml",
				Path:     ".github/workflows/c.yml",
				Content:  []byte(leafYAML),
				RepoSlug: "org/middle",
			},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "nested callee (2 levels) with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_NestedReusableWorkflow_ThreeLevels(t *testing.T) {
	// A → B → C → D, where D has self-hosted. Three levels of indirection.
	callerYAML := `
name: CI
on: push
jobs:
  call-b:
    uses: org/b/.github/workflows/b.yml@main
`
	bYAML := `
name: B
on: workflow_call
jobs:
  call-c:
    uses: org/c/.github/workflows/c.yml@main
`
	cYAML := `
name: C
on: workflow_call
jobs:
  call-d:
    uses: ./.github/workflows/d.yml
`
	dYAML := `
name: D
on: workflow_call
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: echo "deep self-hosted"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		"org/b": {
			{Name: "b.yml", Path: ".github/workflows/b.yml", Content: []byte(bYAML), RepoSlug: "org/b"},
		},
		"org/c": {
			{Name: "c.yml", Path: ".github/workflows/c.yml", Content: []byte(cYAML), RepoSlug: "org/c"},
			{Name: "d.yml", Path: ".github/workflows/d.yml", Content: []byte(dYAML), RepoSlug: "org/c"},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1, "nested callee (3 levels) with self-hosted runner should produce a finding")
	assert.Equal(t, detections.VulnSelfHostedRunner, findings[0].Type)
}

func TestRunnerPlugin_NestedReusableWorkflow_DepthLimitFailsOpen(t *testing.T) {
	// Build a chain deeper than maxReusableWorkflowDepth (4).
	// Each level calls the next. Should fail open (0 findings), not panic.
	callerYAML := `
name: CI
on: push
jobs:
  call-l1:
    uses: org/r/.github/workflows/l1.yml@main
`
	makeLevel := func(next string) string {
		return fmt.Sprintf(`
name: Level
on: workflow_call
jobs:
  next:
    uses: %s
`, next)
	}

	allWorkflows := map[string][]platforms.Workflow{
		"org/r": {
			{Name: "l1.yml", Path: ".github/workflows/l1.yml", Content: []byte(makeLevel("org/r/.github/workflows/l2.yml@main")), RepoSlug: "org/r"},
			{Name: "l2.yml", Path: ".github/workflows/l2.yml", Content: []byte(makeLevel("org/r/.github/workflows/l3.yml@main")), RepoSlug: "org/r"},
			{Name: "l3.yml", Path: ".github/workflows/l3.yml", Content: []byte(makeLevel("org/r/.github/workflows/l4.yml@main")), RepoSlug: "org/r"},
			{Name: "l4.yml", Path: ".github/workflows/l4.yml", Content: []byte(makeLevel("org/r/.github/workflows/l5.yml@main")), RepoSlug: "org/r"},
			{Name: "l5.yml", Path: ".github/workflows/l5.yml", Content: []byte(`
name: Deep Leaf
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "too deep"
`), RepoSlug: "org/r"},
		},
	}

	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "chain exceeding max depth should fail open with 0 findings")
}

func TestRunnerPlugin_NestedReusableWorkflow_WrongSlugNoFalsePositive(t *testing.T) {
	// A calls B in org/middle. B calls ./.github/workflows/c.yml (local to org/middle).
	// c.yml only exists in owner/repo, NOT in org/middle.
	// Should NOT resolve — the local ref must use B's repo slug, not A's.
	callerYAML := `
name: CI
on: push
jobs:
  call-b:
    uses: org/middle/.github/workflows/b.yml@main
`
	middleYAML := `
name: Middle
on: workflow_call
jobs:
  call-c:
    uses: ./.github/workflows/c.yml
`
	selfHostedYAML := `
name: SelfHosted
on: workflow_call
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo "self-hosted"
`
	g, err := analysis.BuildGraph("owner/repo", ".github/workflows/ci.yml", []byte(callerYAML))
	require.NoError(t, err)

	allWorkflows := map[string][]platforms.Workflow{
		"org/middle": {
			{Name: "b.yml", Path: ".github/workflows/b.yml", Content: []byte(middleYAML), RepoSlug: "org/middle"},
			// c.yml is NOT here — it's missing from org/middle
		},
		"owner/repo": {
			// c.yml exists here but should NOT be used for B's local ./ reference
			{Name: "c.yml", Path: ".github/workflows/c.yml", Content: []byte(selfHostedYAML), RepoSlug: "owner/repo"},
		},
	}
	g.SetMetadata("all_workflows", allWorkflows)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "local ref in B should resolve against org/middle, not owner/repo")
}
