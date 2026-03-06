// Package attacks provides the attack plugin interface for CI/CD exploitation
package attacks

import (
	"context"
	"time"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// AttackPlugin executes offensive operations against CI/CD vulnerabilities
type AttackPlugin interface {
	// Identity
	Name() string
	Description() string
	Category() AttackCategory

	// Applicability - determines if attack can be executed based on findings
	CanAttack(findings []detections.Finding) bool

	// Execution
	Execute(ctx context.Context, opts AttackOptions) (*AttackResult, error)

	// Cleanup
	Cleanup(ctx context.Context, session *Session) error
}

// AttackPluginFactory creates new attack plugin instances
type AttackPluginFactory func() AttackPlugin

// AttackCategory classifies the type of attack
type AttackCategory string

const (
	CategorySecrets     AttackCategory = "secrets"     // Secrets exfiltration
	CategoryCICD        AttackCategory = "cicd"        // CI/CD pipeline attacks
	CategoryRunners     AttackCategory = "runners"     // Runner-based attacks
	CategoryPersistence AttackCategory = "persistence" // Persistence mechanisms
	CategoryC2          AttackCategory = "c2"          // Command and control
	CategoryRecon       AttackCategory = "recon"       // Reconnaissance and service discovery
)

// AttackOptions configures attack execution
type AttackOptions struct {
	// Target information
	Target   platforms.Target
	Platform platforms.Platform

	// Detection context
	Findings []detections.Finding // Findings from detection phase

	// Execution control
	DryRun  bool          // Preview without executing
	Verbose bool          // Detailed output
	Timeout time.Duration // Execution timeout

	// Session tracking
	SessionID string // Links to cleanup tracking

	// Attack-specific options
	Payload   string            // Custom payload/script
	Branch    string            // Branch for PR attacks
	ExtraOpts map[string]string // Plugin-specific options
}

// AttackResult contains the outcome of an attack execution
type AttackResult struct {
	// Identity
	Plugin    string    `json:"plugin"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	// Target
	Repo string `json:"repo,omitempty"` // specific repo (owner/repo) this result targets

	// Outcome
	Success bool   `json:"success"`
	Message string `json:"message"`

	// Data collected
	Data      interface{} `json:"data,omitempty"`      // Plugin-specific data (e.g., secrets)
	Artifacts []Artifact  `json:"artifacts,omitempty"` // Created resources

	// Cleanup information
	CleanupActions []CleanupAction `json:"cleanup_actions,omitempty"`
}

// Artifact represents a resource created during attack
type Artifact struct {
	Type        ArtifactType `json:"type"`
	Identifier  string       `json:"identifier"` // PR number, file path, etc.
	URL         string       `json:"url,omitempty"`
	Description string       `json:"description"`
}

// ArtifactType classifies created resources
type ArtifactType string

const (
	ArtifactPR         ArtifactType = "pull_request"
	ArtifactBranch     ArtifactType = "branch"
	ArtifactFile       ArtifactType = "file"
	ArtifactWorkflow   ArtifactType = "workflow"
	ArtifactRepository ArtifactType = "repository"
	ArtifactComment    ArtifactType = "comment"
	ArtifactIssue      ArtifactType = "issue"
)

// CleanupAction describes how to undo an attack artifact
type CleanupAction struct {
	Type        ArtifactType `json:"type"`
	Identifier  string       `json:"identifier"`
	Action      string       `json:"action"` // "delete", "close", "revert"
	Description string       `json:"description"`
}
