package prattack

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestPRAttack_CanAttack(t *testing.T) {
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
			name:     "with injection only",
			findings: []detections.Finding{{Type: detections.VulnActionsInjection}},
			expected: false,
		},
		{
			name:     "empty findings",
			findings: []detections.Finding{},
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

func TestPRAttack_Metadata(t *testing.T) {
	plugin := New()

	assert.Equal(t, "pr-attack", plugin.Name())
	assert.NotEmpty(t, plugin.Description())
	assert.Equal(t, attacks.CategoryCICD, plugin.Category())
}
