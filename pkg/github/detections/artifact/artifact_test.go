package artifact

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestArtifactPoisoningPlugin_DetectsDownloadAndExecution(t *testing.T) {
	yaml := `
name: Workflow Run Artifact
on: workflow_run
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
      - run: ./deploy.sh
`
	g, err := analysis.BuildGraph("owner/repo", "artifact.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnArtifactPoison, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "workflow_run", findings[0].Trigger)
}

func TestArtifactPoisoningPlugin_DetectsNpmBuild(t *testing.T) {
	yaml := `
name: Workflow Run NPM
on: workflow_run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: npm run build
`
	g, err := analysis.BuildGraph("owner/repo", "npm.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnArtifactPoison, findings[0].Type)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
}

func TestArtifactPoisoningPlugin_SafeDownloadWithoutExecution(t *testing.T) {
	yaml := `
name: Safe Artifact Download
on: workflow_run
jobs:
  download:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
`
	g, err := analysis.BuildGraph("owner/repo", "safe-download.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}

func TestArtifactPoisoningPlugin_SafeNoArtifactDownload(t *testing.T) {
	yaml := `
name: No Artifact
on: workflow_run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`
	g, err := analysis.BuildGraph("owner/repo", "no-artifact.yml", []byte(yaml))
	require.NoError(t, err)

	plugin := New()
	findings, err := plugin.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0)
}
