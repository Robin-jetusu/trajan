package gitlab

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// TestFilterFindingsBySeverity tests severity filtering logic
func TestFilterFindingsBySeverity(t *testing.T) {
	tests := []struct {
		name          string
		findings      []detections.Finding
		severitySpec  string
		expectedCount int
		expectError   bool
	}{
		{
			name: "filter critical only",
			findings: []detections.Finding{
				{Severity: detections.SeverityCritical},
				{Severity: detections.SeverityHigh},
				{Severity: detections.SeverityMedium},
			},
			severitySpec:  "critical",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "filter critical and high",
			findings: []detections.Finding{
				{Severity: detections.SeverityCritical},
				{Severity: detections.SeverityHigh},
				{Severity: detections.SeverityMedium},
				{Severity: detections.SeverityLow},
			},
			severitySpec:  "critical,high",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "empty severity spec returns all",
			findings: []detections.Finding{
				{Severity: detections.SeverityCritical},
				{Severity: detections.SeverityHigh},
			},
			severitySpec:  "",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "invalid severity level",
			findings: []detections.Finding{
				{Severity: detections.SeverityHigh},
			},
			severitySpec:  "invalid",
			expectedCount: 0,
			expectError:   true,
		},
		{
			name: "filter with spaces",
			findings: []detections.Finding{
				{Severity: detections.SeverityHigh},
				{Severity: detections.SeverityMedium},
			},
			severitySpec:  "high, medium",
			expectedCount: 2,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := cmdutil.FilterFindingsBySeverity(tt.findings, tt.severitySpec)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(filtered) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d", tt.expectedCount, len(filtered))
			}
		})
	}
}

// TestFilterFindingsByCapabilities tests capability filtering logic
func TestFilterFindingsByCapabilities(t *testing.T) {
	tests := []struct {
		name             string
		findings         []detections.Finding
		capabilitiesSpec string
		expectedCount    int
	}{
		{
			name: "filter single capability",
			findings: []detections.Finding{
				{Type: detections.VulnActionsInjection},
				{Type: detections.VulnExcessivePermissions},
			},
			capabilitiesSpec: "actions_injection",
			expectedCount:    1,
		},
		{
			name: "filter multiple capabilities",
			findings: []detections.Finding{
				{Type: detections.VulnActionsInjection},
				{Type: detections.VulnExcessivePermissions},
				{Type: detections.VulnUnpinnedAction},
			},
			capabilitiesSpec: "actions_injection,excessive_permissions",
			expectedCount:    2,
		},
		{
			name: "empty spec returns all",
			findings: []detections.Finding{
				{Type: detections.VulnActionsInjection},
				{Type: detections.VulnExcessivePermissions},
			},
			capabilitiesSpec: "",
			expectedCount:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := cmdutil.FilterFindingsByCapabilities(tt.findings, tt.capabilitiesSpec)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(filtered) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d", tt.expectedCount, len(filtered))
			}
		})
	}
}
