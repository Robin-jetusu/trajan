// pkg/gitlab/types.go
package gitlab

import "time"

// ProjectPermissions represents the user's access permissions to a project
type ProjectPermissions struct {
	ProjectAccess *AccessInfo `json:"project_access"`
	GroupAccess   *AccessInfo `json:"group_access"`
}

// AccessInfo represents access level information
type AccessInfo struct {
	AccessLevel int `json:"access_level"`
}

// Project represents a GitLab project (repository)
type Project struct {
	ID                int                 `json:"id"`
	Name              string              `json:"name"`
	Path              string              `json:"path"`
	PathWithNamespace string              `json:"path_with_namespace"` // "owner/project"
	DefaultBranch     string              `json:"default_branch"`
	Visibility        string              `json:"visibility"` // public, internal, private
	Archived          bool                `json:"archived"`
	ArchivedAt        string              `json:"archived_at,omitempty"`
	JobsEnabled       bool                `json:"jobs_enabled"`
	WebURL            string              `json:"web_url"`
	Namespace         Namespace           `json:"namespace"`
	Permissions       *ProjectPermissions `json:"permissions,omitempty"`
}

// Namespace represents a GitLab namespace (user or group)
type Namespace struct {
	Name     string `json:"name"`
	FullPath string `json:"full_path"` // e.g., "groupname" or "username"
}

// FileResponse represents a GitLab file API response
type FileResponse struct {
	FileName string `json:"file_name"`
	FilePath string `json:"file_path"`
	Content  string `json:"content"`  // Base64-encoded content
	Encoding string `json:"encoding"` // "base64" or "text"
	BlobID   string `json:"blob_id"`  // SHA
}

// User represents a GitLab user from /user endpoint
type User struct {
	ID               int    `json:"id"`
	Username         string `json:"username"`
	Name             string `json:"name"`
	Email            string `json:"email"`
	State            string `json:"state"`
	AvatarURL        string `json:"avatar_url"`
	WebURL           string `json:"web_url"`
	IsAdmin          bool   `json:"is_admin"`
	Bot              bool   `json:"bot"`
	CanCreateGroup   bool   `json:"can_create_group"`
	CanCreateProject bool   `json:"can_create_project"`
}

// PersonalAccessToken represents token info from /personal_access_tokens/self
type PersonalAccessToken struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	Scopes    []string  `json:"scopes"`
	UserID    int       `json:"user_id"`
	Active    bool      `json:"active"`
	ExpiresAt *string   `json:"expires_at"` // Can be null
}

// Group represents a GitLab group
type Group struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	FullPath   string `json:"full_path"`
	Visibility string `json:"visibility"` // public, internal, private
	WebURL     string `json:"web_url"`
	ParentID   *int   `json:"parent_id"` // nil for top-level groups
}

// SharedGroup represents a group shared with another group
type SharedGroup struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	FullPath         string `json:"full_path"`
	Visibility       string `json:"visibility"`
	GroupAccessLevel int    `json:"group_access_level"`
}

// Member represents a project or group member with access level
type Member struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	State       string `json:"state"`
	AccessLevel int    `json:"access_level"` // 10=Guest, 20=Reporter, etc.
}

// ProjectMember represents a project member with access level
type ProjectMember struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	AccessLevel int    `json:"access_level"` // 10=Guest, 20=Reporter, 30=Developer, 40=Maintainer, 50=Owner
	RoleName    string `json:"-"`            // Computed from AccessLevel
}

// Pipeline represents a CI/CD pipeline
type Pipeline struct {
	ID        int    `json:"id"`
	Status    string `json:"status"`
	Ref       string `json:"ref"`
	SHA       string `json:"sha"`
	WebURL    string `json:"web_url"`
	CreatedAt string `json:"created_at"`
}

// Variable represents a CI/CD variable
type Variable struct {
	Key              string `json:"key"`
	Value            string `json:"value"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	EnvironmentScope string `json:"environment_scope"`
	VariableType     string `json:"variable_type"` // "env_var" or "file"
	Hidden           bool   `json:"hidden"`        // true if variable is masked
}

// Branch represents a Git branch
type Branch struct {
	Name   string `json:"name"`
	Commit struct {
		ID string `json:"id"` // SHA
	} `json:"commit"`
	Protected bool `json:"protected"`
}

// Job represents a CI/CD pipeline job
type Job struct {
	ID         int                    `json:"id"`
	Name       string                 `json:"name"`
	Status     string                 `json:"status"`
	Stage      string                 `json:"stage"`
	Runner     map[string]interface{} `json:"runner,omitempty"` // From log analysis branch
	Ref        string                 `json:"ref"`
	CreatedAt  string                 `json:"created_at"`
	StartedAt  string                 `json:"started_at"`
	FinishedAt string                 `json:"finished_at"`
	WebURL     string                 `json:"web_url"`
	// Pipeline field omitted - can be object or int depending on endpoint
}

// CommitAction represents an action in a commit (create, update, delete file)
type CommitAction struct {
	Action   string `json:"action"` // "create", "update", "delete"
	FilePath string `json:"file_path"`
	Content  string `json:"content,omitempty"`
}

// Commit represents a Git commit
type Commit struct {
	ID        string `json:"id"`
	ShortID   string `json:"short_id"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}
