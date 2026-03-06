package runner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
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
