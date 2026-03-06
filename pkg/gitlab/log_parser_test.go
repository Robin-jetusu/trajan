package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJobTrace_SelfHostedRunner(t *testing.T) {
	trace := `Running with gitlab-runner 18.9.0 (abc123def) on trajan-test (xyz789)
Running on machine-1 via GitLab Runner
Executor: docker
Preparing environment
00:01
Running on runner-pod-abc123 via gitlab-runner-controller...
`

	info, err := ParseJobTrace(trace)
	require.NoError(t, err)

	assert.Equal(t, "trajan-test", info.RunnerName)
	assert.Equal(t, "machine-1", info.MachineName)
	assert.Equal(t, "18.9.0", info.Version)
	assert.Equal(t, "docker", info.Executor)
	assert.True(t, info.IsSelfHosted)
}

func TestParseJobTrace_GitLabSharedRunner(t *testing.T) {
	trace := `Running with gitlab-runner 16.5.0 (abc123) on saas-linux-small-amd64 (xyz789)
Executor: docker+machine
`

	info, err := ParseJobTrace(trace)
	require.NoError(t, err)

	assert.Contains(t, info.RunnerName, "saas-linux")
	assert.False(t, info.IsSelfHosted)
}

func TestParseJobTrace_EmptyTrace(t *testing.T) {
	info, err := ParseJobTrace("")

	assert.Error(t, err)
	assert.Nil(t, info)
}

func TestParseJobTrace_NoRunnerName(t *testing.T) {
	trace := `Some log output without runner information
Executor: shell
`

	info, err := ParseJobTrace(trace)

	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "could not extract runner name")
}
