package jenkins

// Job represents a Jenkins job/pipeline
type Job struct {
	Class    string `json:"_class"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Color    string `json:"color"`
	FullName string `json:"fullName,omitempty"`
	InFolder bool   `json:"inFolder,omitempty"`
	Jobs     []Job  `json:"jobs,omitempty"` // For folder recursion
}

// JobsResponse wraps the Jenkins API response for listing jobs
type JobsResponse struct {
	Jobs []Job `json:"jobs"`
}

// CrumbInfo holds Jenkins CSRF crumb data
type CrumbInfo struct {
	Crumb             string `json:"crumb"`
	CrumbRequestField string `json:"crumbRequestField"`
}

// ServerInfo represents Jenkins server metadata from /api/json
type ServerInfo struct {
	Mode            string `json:"mode"` // NORMAL or EXCLUSIVE
	NodeDescription string `json:"nodeDescription"`
	NodeName        string `json:"nodeName"`
	NumExecutors    int    `json:"numExecutors"`
	UseCrumbs       bool   `json:"useCrumbs"`
	UseSecurity     bool   `json:"useSecurity"`
	Version         string `json:"-"` // Parsed from X-Jenkins response header
}

// WhoAmI represents the response from /whoAmI/api/json
type WhoAmI struct {
	Name        string   `json:"name"`
	Anonymous   bool     `json:"anonymous"`
	Authorities []string `json:"authorities"`
}

// Node represents a Jenkins build agent from /computer/api/json
type Node struct {
	DisplayName        string  `json:"displayName"`
	Offline            bool    `json:"offline"`
	TemporarilyOffline bool    `json:"temporarilyOffline"`
	Idle               bool    `json:"idle"`
	NumExecutors       int     `json:"numExecutors"`
	AssignedLabels     []Label `json:"assignedLabels"`
}

// Label represents a Jenkins node label
type Label struct {
	Name string `json:"name"`
}

// NodesResponse wraps the Jenkins API response for /computer/api/json
type NodesResponse struct {
	Computer []Node `json:"computer"`
}

// PluginInfo represents an installed Jenkins plugin
type PluginInfo struct {
	ShortName string `json:"shortName"`
	Version   string `json:"version"`
	Active    bool   `json:"active"`
	Enabled   bool   `json:"enabled"`
	HasUpdate bool   `json:"hasUpdate"`
	LongName  string `json:"longName"`
}

// PluginsResponse wraps the Jenkins API response for /pluginManager/api/json
type PluginsResponse struct {
	Plugins []PluginInfo `json:"plugins"`
}

// BuildInfo represents a Jenkins build
type BuildInfo struct {
	Number    int    `json:"number"`
	Result    string `json:"result"` // SUCCESS, FAILURE, UNSTABLE, ABORTED
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
	URL       string `json:"url"`
}
