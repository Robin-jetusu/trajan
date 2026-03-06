package includes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestIncludeInjection_DetectsRemoteInclude(t *testing.T) {
	yaml := `
include:
  - remote: 'https://external.com/malicious.yml'

test_job:
  script:
    - echo "test"
`
	g, err := analysis.BuildGraph("group/repo", ".gitlab-ci.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnIncludeInjection, findings[0].Type)
	assert.Equal(t, "gitlab", findings[0].Platform)
	assert.Equal(t, detections.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Evidence, "https://external.com/malicious.yml")
}

func TestIncludeInjection_DetectsCrossProjectInclude(t *testing.T) {
	yaml := `
include:
  - project: 'other/project'
    file: '/templates/ci.yml'

test_job:
  script:
    - echo "test"
`
	g, err := analysis.BuildGraph("group/repo", ".gitlab-ci.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnIncludeInjection, findings[0].Type)
	assert.Equal(t, "gitlab", findings[0].Platform)
	assert.Contains(t, findings[0].Evidence, "other/project")
}

func TestIncludeInjection_IgnoresLocalInclude(t *testing.T) {
	yaml := `
include:
  - local: '/templates/ci.yml'

test_job:
  script:
    - echo "test"
`
	g, err := analysis.BuildGraph("group/repo", ".gitlab-ci.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "local includes should not be flagged")
}

func TestIncludeInjection_IgnoresGitLabTemplate(t *testing.T) {
	yaml := `
include:
  - template: 'Auto-DevOps.gitlab-ci.yml'

test_job:
  script:
    - echo "test"
`
	g, err := analysis.BuildGraph("group/repo", ".gitlab-ci.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	assert.Len(t, findings, 0, "GitLab templates should not be flagged")
}

func TestIncludeInjection_DetectsVariableInterpolation(t *testing.T) {
	yaml := `
include:
  - remote: $CI_MERGE_REQUEST_SOURCE_PROJECT_URL/.gitlab-ci.yml

test_job:
  script:
    - echo "test"
`
	g, err := analysis.BuildGraph("group/repo", ".gitlab-ci.yml", []byte(yaml))
	require.NoError(t, err)

	detection := New()
	findings, err := detection.Detect(context.Background(), g)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detections.VulnIncludeInjection, findings[0].Type)
	assert.Contains(t, findings[0].Evidence, "CI_MERGE_REQUEST_SOURCE_PROJECT_URL")
	assert.Equal(t, detections.SeverityCritical, findings[0].Severity, "variable interpolation should be critical")
}
