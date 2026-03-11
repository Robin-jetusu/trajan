package runner

import (
	"context"
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
