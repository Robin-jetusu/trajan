package common

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestFindingHasType(t *testing.T) {
	findings := []detections.Finding{
		{Type: detections.VulnActionsInjection, Workflow: "ci.yml"},
		{Type: detections.VulnPwnRequest, Workflow: "pr.yml"},
	}

	// Positive cases
	assert.True(t, FindingHasType(findings, detections.VulnActionsInjection))
	assert.True(t, FindingHasType(findings, detections.VulnPwnRequest))

	// Negative cases
	assert.False(t, FindingHasType(findings, detections.VulnSelfHostedRunner))
	assert.False(t, FindingHasType(nil, detections.VulnActionsInjection))
	assert.False(t, FindingHasType([]detections.Finding{}, detections.VulnActionsInjection))
}

func TestFindingsBySeverity(t *testing.T) {
	findings := []detections.Finding{
		{Severity: detections.SeverityInfo, Workflow: "info.yml"},
		{Severity: detections.SeverityLow, Workflow: "low.yml"},
		{Severity: detections.SeverityMedium, Workflow: "medium.yml"},
		{Severity: detections.SeverityHigh, Workflow: "high.yml"},
		{Severity: detections.SeverityCritical, Workflow: "critical.yml"},
	}

	// Filter by medium and above
	result := FindingsBySeverity(findings, detections.SeverityMedium)
	assert.Len(t, result, 3)

	// Filter by critical only
	result = FindingsBySeverity(findings, detections.SeverityCritical)
	assert.Len(t, result, 1)
	assert.Equal(t, "critical.yml", result[0].Workflow)

	// Filter includes all (info)
	result = FindingsBySeverity(findings, detections.SeverityInfo)
	assert.Len(t, result, 5)

	// Empty findings
	result = FindingsBySeverity(nil, detections.SeverityHigh)
	assert.Len(t, result, 0)
}

func TestGetInjectableWorkflows(t *testing.T) {
	findings := []detections.Finding{
		{Type: detections.VulnActionsInjection, Workflow: "ci.yml"},
		{Type: detections.VulnActionsInjection, Workflow: "ci.yml"}, // Duplicate
		{Type: detections.VulnActionsInjection, Workflow: "build.yml"},
		{Type: detections.VulnPwnRequest, Workflow: "pr.yml"}, // Wrong type
	}

	workflows := GetInjectableWorkflows(findings)

	assert.Len(t, workflows, 2)
	assert.Contains(t, workflows, "ci.yml")
	assert.Contains(t, workflows, "build.yml")
	assert.NotContains(t, workflows, "pr.yml")
}

func TestGetPwnRequestWorkflows(t *testing.T) {
	findings := []detections.Finding{
		{Type: detections.VulnPwnRequest, Workflow: "pr-target.yml"},
		{Type: detections.VulnPwnRequest, Workflow: "pr-target.yml"}, // Duplicate
		{Type: detections.VulnActionsInjection, Workflow: "ci.yml"},  // Wrong type
	}

	workflows := GetPwnRequestWorkflows(findings)

	assert.Len(t, workflows, 1)
	assert.Contains(t, workflows, "pr-target.yml")
}

func TestHasCriticalFindings(t *testing.T) {
	// With critical
	findings := []detections.Finding{
		{Severity: detections.SeverityMedium},
		{Severity: detections.SeverityCritical},
	}
	assert.True(t, HasCriticalFindings(findings))

	// Without critical
	findings = []detections.Finding{
		{Severity: detections.SeverityHigh},
		{Severity: detections.SeverityMedium},
	}
	assert.False(t, HasCriticalFindings(findings))

	// Empty
	assert.False(t, HasCriticalFindings(nil))
}
