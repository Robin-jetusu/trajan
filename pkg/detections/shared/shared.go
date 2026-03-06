// modules/trajan/pkg/detections/shared/shared.go
// Package shared provides cross-platform detection logic
package shared

import (
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// Detector is a platform-agnostic detection component
// Implementations analyze specific vulnerability patterns
type Detector interface {
	// Detect analyzes a step and returns a finding if vulnerable
	// Returns nil if no vulnerability detected
	Detect(step *graph.StepNode, ctx *DetectionContext) *detections.Finding
}

// DetectionContext provides platform-specific context for detection
type DetectionContext struct {
	Platform   string // "github", "gitlab", "bitbucket", "azure"
	Workflow   *graph.WorkflowNode
	Job        *graph.JobNode
	Repository string

	// Platform-specific adapters
	UsesResolver   UsesResolver   // Resolves "uses" references
	PinValidator   PinValidator   // Validates pinning
	SecretDetector SecretDetector // Detects secret patterns
}

// UsesResolver resolves "uses" or equivalent references across platforms
type UsesResolver interface {
	// Parse parses a uses reference into components
	// GitHub: "actions/checkout@v3" -> {owner: "actions", repo: "checkout", ref: "v3"}
	// GitLab: "include: remote: ..." -> different structure
	Parse(uses string) (*UsesReference, error)
}

// UsesReference represents a resolved dependency reference
type UsesReference struct {
	Type     UsesType // Action, Docker, Local, Include
	Owner    string   // Repository owner/namespace
	Repo     string   // Repository name
	Path     string   // Path within repo (e.g., "action/subfolder")
	Ref      string   // Version reference (tag, branch, SHA)
	IsPinned bool     // True if pinned to SHA
	IsLocal  bool     // True if local reference
	RawValue string   // Original string
}

// UsesType categorizes the dependency type
type UsesType string

const (
	UsesTypeAction   UsesType = "action"   // GitHub Action, GitLab Include
	UsesTypeDocker   UsesType = "docker"   // Docker image
	UsesTypeLocal    UsesType = "local"    // Local file reference
	UsesTypePipe     UsesType = "pipe"     // BitBucket Pipe
	UsesTypeTemplate UsesType = "template" // Azure Template
)

// PinValidator validates version pinning
type PinValidator interface {
	// IsPinned returns true if the reference is properly pinned
	IsPinned(ref *UsesReference) bool

	// ValidateSHA validates SHA format for the platform
	ValidateSHA(sha string) bool
}

// SecretDetector detects potential secret exposure
type SecretDetector interface {
	// DetectSecretPattern checks if a string might expose secrets
	DetectSecretPattern(value string) []SecretMatch
}

// SecretMatch represents a detected secret pattern
type SecretMatch struct {
	Pattern    string
	Confidence detections.Confidence
	Location   string
}

// NewDetectionContext creates a new detection context
func NewDetectionContext(platform string, wf *graph.WorkflowNode) *DetectionContext {
	return &DetectionContext{
		Platform:   platform,
		Workflow:   wf,
		Repository: wf.RepoSlug,
	}
}
