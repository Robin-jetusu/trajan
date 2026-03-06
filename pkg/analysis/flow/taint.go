// modules/trajan/pkg/analysis/flow/taint.go
package flow

import "time"

// TaintSource identifies where tainted data originates
type TaintSource string

const (
	// TaintSourceUserInput - directly controlled by external users
	TaintSourceUserInput TaintSource = "user_input"

	// TaintSourceFork - from a forked repository (less trusted)
	TaintSourceFork TaintSource = "fork"

	// TaintSourceExternal - from external services/APIs
	TaintSourceExternal TaintSource = "external"

	// TaintSourceArtifact - from uploaded artifacts
	TaintSourceArtifact TaintSource = "artifact"

	// TaintSourceCache - from potentially poisoned cache
	TaintSourceCache TaintSource = "cache"

	// TaintSourceAI - processed by AI/LLM (potential injection vector)
	TaintSourceAI TaintSource = "ai_processed"
)

// TaintedValue represents a value that may contain untrusted data
type TaintedValue struct {
	// Value is the actual string value
	Value string

	// Source identifies the origin of the taint
	Source TaintSource

	// Path tracks the propagation path from source to current location
	// e.g., ["github.event.comment.body", "env.BODY", "steps.extract.outputs.data"]
	Path []string

	// Confidence indicates how certain we are about the taint
	Confidence Confidence

	// OriginalRef is the original context reference
	OriginalRef string

	// Timestamp when taint was first detected
	Timestamp time.Time

	// Metadata for additional context (platform-specific)
	Metadata map[string]string
}

// NewTaintedValue creates a new tainted value at its source
func NewTaintedValue(value string, source TaintSource, originRef string) *TaintedValue {
	return &TaintedValue{
		Value:       value,
		Source:      source,
		Path:        []string{originRef},
		Confidence:  ConfidenceHigh,
		OriginalRef: originRef,
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
	}
}

// PropagateThrough creates a new TaintedValue that has passed through a variable
func (tv *TaintedValue) PropagateThrough(variable string) *TaintedValue {
	newPath := make([]string, len(tv.Path)+1)
	copy(newPath, tv.Path)
	newPath[len(tv.Path)] = variable

	return &TaintedValue{
		Value:       tv.Value,
		Source:      tv.Source,
		Path:        newPath,
		Confidence:  tv.Confidence,
		OriginalRef: tv.OriginalRef,
		Timestamp:   tv.Timestamp,
		Metadata:    copyMap(tv.Metadata),
	}
}

// Sanitized creates a new TaintedValue with reduced confidence after sanitization
func (tv *TaintedValue) Sanitized(method string) *TaintedValue {
	newPath := make([]string, len(tv.Path)+1)
	copy(newPath, tv.Path)
	newPath[len(tv.Path)] = "sanitized:" + method

	newConfidence := tv.Confidence
	switch tv.Confidence {
	case ConfidenceHigh:
		newConfidence = ConfidenceMedium
	case ConfidenceMedium:
		newConfidence = ConfidenceLow
	}

	return &TaintedValue{
		Value:       tv.Value,
		Source:      tv.Source,
		Path:        newPath,
		Confidence:  newConfidence,
		OriginalRef: tv.OriginalRef,
		Timestamp:   tv.Timestamp,
		Metadata:    copyMap(tv.Metadata),
	}
}

// IsTainted returns true if this value should be treated as untrusted
func (tv *TaintedValue) IsTainted() bool {
	return tv.Source != "" && tv.Confidence != ConfidenceLow
}

// String returns a human-readable representation
func (tv *TaintedValue) String() string {
	return tv.OriginalRef + " -> " + tv.Path[len(tv.Path)-1]
}
