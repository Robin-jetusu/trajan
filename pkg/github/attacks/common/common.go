package common

import (
	"math/rand"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

// FindingHasType checks if any finding matches the given type.
// Delegates to detections.FindingHasType.
func FindingHasType(findings []detections.Finding, vulnType detections.VulnerabilityType) bool {
	return detections.FindingHasType(findings, vulnType)
}

// FindingsBySeverity returns findings at or above the given severity
func FindingsBySeverity(findings []detections.Finding, minSeverity detections.Severity) []detections.Finding {
	severityOrder := map[detections.Severity]int{
		detections.SeverityInfo:     0,
		detections.SeverityLow:      1,
		detections.SeverityMedium:   2,
		detections.SeverityHigh:     3,
		detections.SeverityCritical: 4,
	}

	minOrder := severityOrder[minSeverity]
	var result []detections.Finding
	for _, f := range findings {
		if severityOrder[f.Severity] >= minOrder {
			result = append(result, f)
		}
	}
	return result
}

// GetInjectableWorkflows returns workflow paths that have injection vulnerabilities
func GetInjectableWorkflows(findings []detections.Finding) []string {
	seen := make(map[string]bool)
	var workflows []string

	for _, f := range findings {
		if f.Type == detections.VulnActionsInjection && !seen[f.Workflow] {
			seen[f.Workflow] = true
			workflows = append(workflows, f.Workflow)
		}
	}
	return workflows
}

// GetPwnRequestWorkflows returns workflow paths that have pwn_request vulnerabilities
func GetPwnRequestWorkflows(findings []detections.Finding) []string {
	seen := make(map[string]bool)
	var workflows []string

	for _, f := range findings {
		if f.Type == detections.VulnPwnRequest && !seen[f.Workflow] {
			seen[f.Workflow] = true
			workflows = append(workflows, f.Workflow)
		}
	}
	return workflows
}

// GetSelfHostedRunnerWorkflows returns workflow paths that use self-hosted runners
func GetSelfHostedRunnerWorkflows(findings []detections.Finding) []string {
	seen := make(map[string]bool)
	var workflows []string

	for _, f := range findings {
		if f.Type == detections.VulnSelfHostedRunner && !seen[f.Workflow] {
			seen[f.Workflow] = true
			workflows = append(workflows, f.Workflow)
		}
	}
	return workflows
}

// FindingsByType returns all findings of a specific type
func FindingsByType(findings []detections.Finding, vulnType detections.VulnerabilityType) []detections.Finding {
	var result []detections.Finding
	for _, f := range findings {
		if f.Type == vulnType {
			result = append(result, f)
		}
	}
	return result
}

// HasCriticalFindings checks if there are any critical severity findings
func HasCriticalFindings(findings []detections.Finding) bool {
	for _, f := range findings {
		if f.Severity == detections.SeverityCritical {
			return true
		}
	}
	return false
}

// GetWorkflowsWithPermissions returns workflows that have overly permissive permissions
func GetWorkflowsWithPermissions(findings []detections.Finding) []string {
	seen := make(map[string]bool)
	var workflows []string

	for _, f := range findings {
		if f.Type == detections.VulnExcessivePermissions && !seen[f.Workflow] {
			seen[f.Workflow] = true
			workflows = append(workflows, f.Workflow)
		}
	}
	return workflows
}

// GenerateRandomString generates a random alphanumeric string
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// GetFindingsByType is an alias for FindingsByType for compatibility
func GetFindingsByType(findings []detections.Finding, vulnType detections.VulnerabilityType) []detections.Finding {
	return FindingsByType(findings, vulnType)
}
