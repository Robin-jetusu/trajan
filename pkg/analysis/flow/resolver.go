package flow

import (
	"regexp"
	"strings"
)

// Expression pattern to extract variable from ${{ ... }}
var exprPattern = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)

// extractVariableName extracts the variable name from a ${{ }} expression
func extractVariableName(input string) string {
	matches := exprPattern.FindStringSubmatch(input)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

// ResolveVariable resolves a variable reference to its github context source
// Returns the resolved variable name and a boolean indicating if resolution succeeded
func (t *Tracker) ResolveVariable(variable string, fc *FlowContext) (string, bool) {
	// Track visited variables to detect circular references
	visited := make(map[string]bool)
	return t.resolveVariableInternal(variable, fc, visited)
}

// resolveVariableInternal is the recursive implementation of ResolveVariable
func (t *Tracker) resolveVariableInternal(variable string, fc *FlowContext, visited map[string]bool) (string, bool) {
	if visited[variable] {
		return variable, false
	}
	visited[variable] = true

	// Handle inputs.X -> lookup in InputLookup
	if strings.HasPrefix(variable, "inputs.") {
		key := strings.TrimPrefix(variable, "inputs.")
		if val, ok := fc.InputLookup[key]; ok {
			extracted := extractVariableName(val)
			if extracted != "" {
				// Recursive resolution
				return t.resolveVariableInternal(extracted, fc, visited)
			}
			return val, true
		}
		return variable, false
	}

	// Handle env.X -> lookup in EnvLookup
	if strings.HasPrefix(variable, "env.") {
		key := strings.TrimPrefix(variable, "env.")
		if val, ok := fc.EnvLookup[key]; ok {
			extracted := extractVariableName(val)
			if extracted != "" {
				// Recursive resolution
				return t.resolveVariableInternal(extracted, fc, visited)
			}
			return val, true
		}
		return variable, false
	}

	if strings.HasPrefix(variable, "steps.") {
		parts := strings.Split(variable, ".")
		if len(parts) >= 4 && parts[2] == "outputs" {
			stepID := parts[1]
			outputName := parts[3]
			key := stepID + "." + outputName
			if val, ok := fc.StepOutputs[key]; ok {
				extracted := extractVariableName(val)
				if extracted != "" {
					// Recursive resolution
					return t.resolveVariableInternal(extracted, fc, visited)
				}
				return val, true
			}
		}
		return variable, false
	}

	// Base case: github.* context
	if strings.HasPrefix(variable, "github.") {
		return variable, true
	}

	// Unknown context (secrets.*, matrix.*, etc.)
	return variable, false
}
