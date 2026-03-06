package workflowinjection

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestWorkflowInjection_CanAttack(t *testing.T) {
	plugin := New()

	testCases := []struct {
		name     string
		findings []detections.Finding
		expected bool
	}{
		{
			name:     "with injection vulnerability",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: true,
		},
		{
			name:     "with pwn request only",
			findings: []detections.Finding{{Type: detections.VulnPwnRequest}},
			expected: false,
		},
		{
			name:     "with no findings",
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

func TestWorkflowInjection_Metadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "workflow-injection", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryCICD, plugin.Category())
}
