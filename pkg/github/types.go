package github

import (
	"fmt"
	"time"
)

// Secret represents a GitHub Actions/Codespaces/Dependabot secret
// Note: GitHub API returns metadata only - secret values are never exposed
type Secret struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	Visibility string    `json:"visibility,omitempty"` // "all", "private", "selected" (org secrets only)
	Source     string    `json:"source,omitempty"`     // "api" or "workflow"
}

// SecretsResponse wraps paginated secrets from GitHub API
type SecretsResponse struct {
	TotalCount int      `json:"total_count"`
	Secrets    []Secret `json:"secrets"`
}

// APIError represents a GitHub API error with context
type APIError struct {
	StatusCode int
	Message    string
	Resource   string // "secrets", "runners"
	Scope      string // "org", "repo"
	Target     string // org/repo name
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API error %d for %s %s (%s): %s",
		e.StatusCode, e.Scope, e.Target, e.Resource, e.Message)
}

// IsPermissionDenied checks if error is 403/404 permission issue
// GitHub returns 404 for private resources to avoid leaking existence
func IsPermissionDenied(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == 403 || apiErr.StatusCode == 404
	}
	return false
}

// SecretsResult contains enumerated secrets from a scan
type SecretsResult struct {
	ActionsSecrets    map[string][]Secret // target -> secrets
	WorkflowSecrets   map[string][]Secret // target -> secrets extracted from workflow YAML
	DependabotSecrets map[string][]Secret // target -> secrets (future)
	CodespacesSecrets map[string][]Secret // target -> secrets (future)
	PermissionErrors  []string            // endpoints that returned 403/404
	Errors            []error             // other errors
}

// Runner represents a GitHub Actions self-hosted runner
type Runner struct {
	ID     int64         `json:"id"`
	Name   string        `json:"name"`
	OS     string        `json:"os"`     // "linux", "windows", "macos"
	Status string        `json:"status"` // "online", "offline"
	Busy   bool          `json:"busy"`   // Currently running a job
	Labels []RunnerLabel `json:"labels"`
}

// RunnerLabel represents a runner label for targeting
type RunnerLabel struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// RunnersResponse wraps paginated runners from GitHub API
type RunnersResponse struct {
	TotalCount int      `json:"total_count"`
	Runners    []Runner `json:"runners"`
}

// RunnerGroup represents a collection of runners
type RunnerGroup struct {
	ID                       int64    `json:"id"`
	Name                     string   `json:"name"`
	Visibility               string   `json:"visibility"` // "all", "selected", "private"
	Default                  bool     `json:"default"`
	AllowsPublicRepositories bool     `json:"allows_public_repositories"`
	RestrictedToWorkflows    bool     `json:"restricted_to_workflows"`
	SelectedWorkflows        []string `json:"selected_workflows"`
	RunnersURL               string   `json:"runners_url"`
	SelectedRepositoriesURL  string   `json:"selected_repositories_url,omitempty"`
}

// RunnerGroupsResponse wraps paginated runner groups from GitHub API
type RunnerGroupsResponse struct {
	TotalCount   int           `json:"total_count"`
	RunnerGroups []RunnerGroup `json:"runner_groups"`
}

// RunnersResult contains enumerated runners from a scan
type RunnersResult struct {
	Runners          map[string][]Runner      // target -> runners
	RunnerGroups     map[string][]RunnerGroup // target -> groups
	PermissionErrors []string
	Errors           []error
}

// TokenInfoResult contains token metadata from a scan
type TokenInfoResult struct {
	TokenInfo        *TokenInfo `json:"token_info,omitempty"`
	PermissionErrors []string   `json:"permission_errors,omitempty"`
	Errors           []error    `json:"errors,omitempty"`
}

// Organization represents a GitHub organization (minimal, from /user/orgs)
type Organization struct {
	Login       string `json:"login"`
	ID          int    `json:"id"`
	Description string `json:"description"`
}

// OrgDetail represents detailed GitHub organization info (from /orgs/{org})
type OrgDetail struct {
	Login                       string `json:"login"`
	ID                          int    `json:"id"`
	Description                 string `json:"description"`
	BillingEmail                string `json:"billing_email,omitempty"`
	TwoFactorRequirementEnabled bool   `json:"two_factor_requirement_enabled"`
}

// Variable represents a GitHub Actions variable (org or repo level)
type Variable struct {
	Name       string    `json:"name"`
	Value      string    `json:"value"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	Visibility string    `json:"visibility,omitempty"` // org vars only: "all", "private", "selected"
}

// VariablesResponse wraps paginated variables from GitHub API
type VariablesResponse struct {
	TotalCount int        `json:"total_count"`
	Variables  []Variable `json:"variables"`
}

// Gist represents a GitHub gist
type Gist struct {
	ID          string            `json:"id"`
	HTMLURL     string            `json:"html_url"`
	Public      bool              `json:"public"`
	Description string            `json:"description"`
	Files       map[string]string `json:"-"` // filename -> raw URL mapping
}

// DeployKeyInput contains parameters for creating a deploy key
type DeployKeyInput struct {
	Title    string `json:"title"`
	Key      string `json:"key"`
	ReadOnly bool   `json:"read_only"`
}

// DeployKey represents a repository deploy key
type DeployKey struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Key       string    `json:"key"`
	ReadOnly  bool      `json:"read_only"`
	Verified  bool      `json:"verified"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}

// RunnerRelease represents a GitHub Actions runner release
type RunnerRelease struct {
	TagName string         `json:"tag_name"`
	Name    string         `json:"name"`
	Assets  []ReleaseAsset `json:"assets"`
}

// ReleaseAsset represents a downloadable asset from a release
type ReleaseAsset struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"browser_download_url"`
}
