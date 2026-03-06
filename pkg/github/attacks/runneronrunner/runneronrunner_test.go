package runneronrunner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestRunnerOnRunner_CanAttack(t *testing.T) {
	plugin := New()

	testCases := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name:     "with pwn request vulnerability",
			findings: []detections.Finding{{Type: detections.VulnPwnRequest}},
			expected: true,
		},
		{
			name:     "with self-hosted runner vulnerability",
			findings: []detections.Finding{{Type: detections.VulnSelfHostedRunner}},
			expected: true,
		},
		{
			name: "with both vulnerabilities",
			findings: []detections.Finding{
				{Type: detections.VulnPwnRequest},
				{Type: detections.VulnSelfHostedRunner},
			},
			expected: true,
		},
		{
			name:     "with unrelated vulnerability",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: false,
		},
		{
			name:     "with no vulnerabilities",
			findings: []detections.Finding{},
			expected: false,
		},
		{
			name:     "nil findings",
			findings: nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := plugin.CanAttack(tc.findings)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestRunnerOnRunner_Metadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "runner-on-runner", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryRunners, plugin.Category())
}

func TestRunnerOnRunner_New(t *testing.T) {
	plugin := New()

	assert.NotNil(t, plugin)
	assert.Equal(t, "runner-on-runner", plugin.Name())
	assert.Equal(t, "github", plugin.Platform())
}
