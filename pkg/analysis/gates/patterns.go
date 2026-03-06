package gates

import (
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/flow"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// GatePattern defines a pattern that indicates a gate
type GatePattern struct {
	Type        flow.GateType
	Description string
	Match       func(node graph.Node) bool
}

// BlockingGates are gates that should suppress findings
var BlockingGates = []flow.GateType{
	flow.GateDeploymentApproval, // Requires human approval
	flow.GatePermissionCheck,    // Validates commenter permissions
}

// SoftGates reduce confidence but don't suppress findings
var SoftGates = []flow.GateType{
	flow.GateLabelRequired,     // Can be bypassed if attacker can add labels
	flow.GateAuthorAssociation, // CONTRIBUTOR check can be bypassed
}

// StandardPatterns returns the built-in gate detection patterns
func StandardPatterns() []GatePattern {
	return []GatePattern{
		// Deployment environment approval
		{
			Type:        flow.GateDeploymentApproval,
			Description: "Job uses environment or has deployment-related name",
			Match: func(node graph.Node) bool {
				if job, ok := node.(*graph.JobNode); ok {
					// Primary: check if job has an explicit environment
					if job.Environment != "" {
						return true
					}
					// Secondary heuristic: naming patterns
					nameLower := strings.ToLower(job.Name)
					return strings.Contains(nameLower, "production") ||
						strings.Contains(nameLower, "deploy") ||
						strings.Contains(nameLower, "release")
				}
				return false
			},
		},

		// Pull request label requirement
		{
			Type:        flow.GateLabelRequired,
			Description: "Workflow triggers on pull_request_target:labeled only",
			Match: func(node graph.Node) bool {
				if wf, ok := node.(*graph.WorkflowNode); ok {
					// Check if workflow only triggers on labeled event
					for _, trigger := range wf.Triggers {
						if strings.Contains(trigger, "labeled") {
							return true
						}
					}
				}
				return false
			},
		},

		// Author association check (only if not using github-script)
		{
			Type:        flow.GateAuthorAssociation,
			Description: "Step checks github.event.comment.author_association",
			Match: func(node graph.Node) bool {
				if step, ok := node.(*graph.StepNode); ok {
					// Skip if using github-script (will be caught by permission check pattern)
					if strings.Contains(step.Uses, "github-script") {
						return false
					}
					// Check if step condition references author_association
					if strings.Contains(step.If, "author_association") {
						return true
					}
					// Check run command for author_association checks
					if strings.Contains(step.Run, "author_association") {
						return true
					}
				}
				return false
			},
		},

		// Permission check via github-script or similar
		{
			Type:        flow.GatePermissionCheck,
			Description: "Step performs permission validation",
			Match: func(node graph.Node) bool {
				if step, ok := node.(*graph.StepNode); ok {
					stepNameLower := strings.ToLower(step.Name)
					stepRunLower := strings.ToLower(step.Run)
					stepIfLower := strings.ToLower(step.If)

					// Common patterns for permission checks
					if strings.Contains(step.Uses, "github-script") {
						// Check for permission validation in run command or if condition
						permissionKeywords := []string{
							"member", "collaborator", "owner",
							"permission", "authorized", "access",
							"author_association",
						}
						for _, keyword := range permissionKeywords {
							if strings.Contains(stepRunLower, keyword) ||
								strings.Contains(stepIfLower, keyword) {
								return true
							}
						}
					}

					// Check for explicit permission validation steps
					if strings.Contains(stepNameLower, "permission") ||
						strings.Contains(stepNameLower, "access") ||
						strings.Contains(stepNameLower, "authorize") {
						return true
					}
				}
				return false
			},
		},
	}
}

// IsBlockingGate returns true if the gate type should suppress findings
func IsBlockingGate(gateType flow.GateType) bool {
	for _, blocking := range BlockingGates {
		if gateType == blocking {
			return true
		}
	}
	return false
}

// IsSoftGate returns true if the gate type should reduce confidence
func IsSoftGate(gateType flow.GateType) bool {
	for _, soft := range SoftGates {
		if gateType == soft {
			return true
		}
	}
	return false
}
