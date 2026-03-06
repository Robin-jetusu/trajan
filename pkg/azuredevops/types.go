// pkg/platforms/azuredevops/types.go
package azuredevops

// Project represents an Azure DevOps project
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	State       string `json:"state"`      // wellFormed, createPending, deleting, new, deleted
	Visibility  string `json:"visibility"` // private, public
}

// Repository represents an Azure DevOps Git repository
type Repository struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	URL           string  `json:"url"`
	DefaultBranch string  `json:"defaultBranch"` // refs/heads/main
	Size          int64   `json:"size"`
	RemoteURL     string  `json:"remoteUrl"` // Git clone URL (HTTPS)
	SSHURL        string  `json:"sshUrl"`    // Git clone URL (SSH)
	WebURL        string  `json:"webUrl"`    // Browser URL
	Project       Project `json:"project"`
	IsDisabled    bool    `json:"isDisabled"`
}

// FileContent represents a file retrieved from a repository
type FileContent struct {
	ObjectID      string `json:"objectId"`      // Git blob SHA
	GitObjectType string `json:"gitObjectType"` // blob, tree, commit
	CommitID      string `json:"commitId"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	// Content is base64-encoded when ContentMetadata.Encoding is "base64"
	Content string `json:"content"`
}

// RepositoryList represents the response from listing repositories
type RepositoryList struct {
	Value []Repository `json:"value"`
	Count int          `json:"count"`
}

// ProjectList represents the response from listing projects
type ProjectList struct {
	Value []Project `json:"value"`
	Count int       `json:"count"`
}

// Pipeline represents an Azure DevOps pipeline
type Pipeline struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Folder string `json:"folder"`
	URL    string `json:"url"`
}

// PipelineList represents the response from listing pipelines
type PipelineList struct {
	Value []Pipeline `json:"value"`
	Count int        `json:"count"`
}

// AgentPool represents an Azure DevOps agent pool
type AgentPool struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	IsHosted      bool   `json:"isHosted"`
	PoolType      string `json:"poolType"`
	Size          int    `json:"size"`
	AutoProvision bool   `json:"autoProvision"`
}

// AgentPoolList represents the response from listing agent pools
type AgentPoolList struct {
	Value []AgentPool `json:"value"`
	Count int         `json:"count"`
}

// VariableGroup represents an Azure DevOps variable group
type VariableGroup struct {
	ID          int                      `json:"id"`
	Name        string                   `json:"name"`
	Type        string                   `json:"type"`
	Description string                   `json:"description"`
	Variables   map[string]VariableValue `json:"variables"`
}

// VariableValue represents a variable in a variable group
type VariableValue struct {
	Value    string `json:"value"`
	IsSecret bool   `json:"isSecret"`
}

// VariableGroupList represents the response from listing variable groups
type VariableGroupList struct {
	Value []VariableGroup `json:"value"`
	Count int             `json:"count"`
}

// ServiceConnection represents an Azure DevOps service connection
type ServiceConnection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	IsReady     bool   `json:"isReady"`
	IsShared    bool   `json:"isShared"`
}

// ServiceConnectionList represents the response from listing service connections
type ServiceConnectionList struct {
	Value []ServiceConnection `json:"value"`
	Count int                 `json:"count"`
}

// ArtifactFeed represents an Azure DevOps artifact feed
type ArtifactFeed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ArtifactFeedList represents the response from listing artifact feeds
type ArtifactFeedList struct {
	Value []ArtifactFeed `json:"value"`
	Count int            `json:"count"`
}

// ConnectionData represents the response from /_apis/connectionData
type ConnectionData struct {
	AuthenticatedUser struct {
		ID                  string `json:"id"`
		ProviderDisplayName string `json:"providerDisplayName"`
	} `json:"authenticatedUser"`
	InstanceID          string `json:"instanceId"` // Organization account ID (used for targetAccounts)
	LocationServiceData struct {
		ServiceOwner string `json:"serviceOwner"`
	} `json:"locationServiceData"`
}

// UserProfile represents the response from profile/profiles/me
type UserProfile struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"emailAddress"`
}
