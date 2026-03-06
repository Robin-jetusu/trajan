// Package parser provides workflow parsing for multiple CI/CD platforms
package parser

import (
	"fmt"
	"sync"
)

// WorkflowParser defines the interface for parsing CI/CD workflow files
type WorkflowParser interface {
	// Platform returns the platform identifier (e.g., "github", "gitlab", "bitbucket", "azure")
	Platform() string

	// CanParse returns true if this parser can handle the given file path
	// This allows automatic parser selection based on file location/naming
	CanParse(path string) bool

	// Parse parses workflow content and returns a generic Workflow representation
	Parse(data []byte) (*NormalizedWorkflow, error)
}

// NormalizedWorkflow represents a generic CI/CD workflow across platforms
// This provides a normalized view for cross-platform detection
type NormalizedWorkflow struct {
	// Platform identifies the source platform (github, gitlab, bitbucket, azure)
	Platform string

	// Name is the workflow display name
	Name string

	// Path is the file path of the workflow
	Path string

	// Triggers lists the events that trigger this workflow
	Triggers []string

	// TriggerLines maps YAML trigger key names (e.g. "trigger", "pr") to their line numbers
	TriggerLines map[string]int

	// Jobs contains the workflow jobs keyed by job ID
	Jobs map[string]*NormalizedJob

	// Permissions at the workflow level
	Permissions *NormalizedPermissions

	// Env contains workflow-level environment variables
	Env map[string]string

	// Raw contains the original parsed structure for platform-specific analysis
	Raw interface{}
}

// NormalizedJob represents a generic CI/CD job
type NormalizedJob struct {
	// ID is the job identifier
	ID string

	// Name is the job display name
	Name string

	// RunsOn specifies the runner/executor
	RunsOn string

	// Needs lists job dependencies
	Needs []string

	// Condition is the job-level conditional (if)
	Condition string

	// Uses specifies a reusable workflow to call (job-level uses)
	Uses string

	// Steps contains the job steps
	Steps []*NormalizedStep

	// Permissions at the job level
	Permissions *NormalizedPermissions

	// Env contains job-level environment variables
	Env map[string]string

	// Outputs defines job outputs
	Outputs map[string]string

	// Services defines service containers (GitHub Actions, GitLab services)
	Services map[string]*NormalizedService

	// Environment is the deployment environment name (for GitHub environment protection)
	Environment string

	// Line is the line number in the YAML file where this job is defined
	Line int

	// RunnerTags are tags for runner selection (GitLab tags field)
	RunnerTags []string

	SelfHosted bool
}

// NormalizedStep represents a generic CI/CD step
type NormalizedStep struct {
	// ID is the step identifier
	ID string

	// Name is the step display name
	Name string

	// Uses specifies an action/template to use (GitHub Actions, Azure tasks, etc.)
	Uses string

	// Run contains shell commands to execute
	Run string

	// With contains input parameters for the action
	With map[string]string

	// Env contains step-level environment variables
	Env map[string]string

	// Line is the line number in the YAML file where this step is defined
	Line int

	// WithLines maps input parameter names to their line numbers in the YAML
	WithLines map[string]int
	// EnvLines maps environment variable names to their line numbers in the YAML
	EnvLines map[string]int

	// Condition is the step-level conditional (if)
	Condition string

	// WorkingDirectory for the step
	WorkingDirectory string

	// Shell specifies the shell to use
	Shell string

	// ContinueOnError allows step to fail without failing the job
	ContinueOnError bool
}

// NormalizedPermissions represents CI/CD permissions configuration
type NormalizedPermissions struct {
	// ReadAll indicates read access to all scopes
	ReadAll bool

	// WriteAll indicates write access to all scopes
	WriteAll bool

	// Scopes maps permission scope to access level (read/write/none)
	Scopes map[string]string
}

// Clone returns a deep copy of the permissions.
func (p *NormalizedPermissions) Clone() *NormalizedPermissions {
	c := &NormalizedPermissions{
		ReadAll:  p.ReadAll,
		WriteAll: p.WriteAll,
		Scopes:   make(map[string]string, len(p.Scopes)),
	}
	for k, v := range p.Scopes {
		c.Scopes[k] = v
	}
	return c
}

// NormalizedService represents a service container
type NormalizedService struct {
	// Image is the container image
	Image string

	// Env contains environment variables
	Env map[string]string

	// Ports lists exposed ports
	Ports []string

	// Options contains additional options
	Options string
}

// ParserRegistry manages workflow parsers
var (
	mu             sync.RWMutex
	parserRegistry = make(map[string]WorkflowParser)
)

// RegisterParser registers a workflow parser for a platform
func RegisterParser(parser WorkflowParser) {
	mu.Lock()
	defer mu.Unlock()
	parserRegistry[parser.Platform()] = parser
}

// GetParser returns the parser for a platform
func GetParser(platform string) WorkflowParser {
	mu.RLock()
	defer mu.RUnlock()
	return parserRegistry[platform]
}

// DetectParser finds the appropriate parser for a file path
func DetectParser(path string) WorkflowParser {
	mu.RLock()
	defer mu.RUnlock()
	for _, parser := range parserRegistry {
		if parser.CanParse(path) {
			return parser
		}
	}
	return nil
}

// Helper functions for YAML type conversions (shared across parsers)

// interfaceSliceToStringSlice converts []interface{} to []string
func interfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if str, ok := item.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

// interfaceMapToStringMap converts map[string]interface{} to map[string]string
func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}
