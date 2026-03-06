package jfrog

// Repository represents a JFrog Artifactory repository.
type Repository struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	PackageType string `json:"packageType"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

// User represents a JFrog user account.
type User struct {
	Name                     string   `json:"name"`
	Email                    string   `json:"email"`
	Admin                    bool     `json:"admin"`
	Groups                   []string `json:"groups,omitempty"`
	LastLoggedIn             string   `json:"lastLoggedIn,omitempty"`
	ProfileUpdatable         bool     `json:"profileUpdatable,omitempty"`
	InternalPasswordDisabled bool     `json:"internalPasswordDisabled,omitempty"`
}

// Group represents a JFrog user group.
type Group struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	AutoJoin    bool   `json:"autoJoin"`
	Realm       string `json:"realm,omitempty"`
	External    bool   `json:"external,omitempty"`
}

// Permission represents a JFrog permission target.
type Permission struct {
	Name string `json:"name"`
	URI  string `json:"uri,omitempty"`
}

// BuildInfo represents JFrog build information.
type BuildInfo struct {
	Name       string            `json:"name"`
	Number     string            `json:"number"`
	Started    string            `json:"started"`
	Properties map[string]string `json:"properties,omitempty"`
	Modules    []ModuleInfo      `json:"modules,omitempty"`
}

// ModuleInfo represents a build module with artifacts and dependencies.
type ModuleInfo struct {
	ID           string           `json:"id"`
	Artifacts    []ArtifactInfo   `json:"artifacts,omitempty"`
	Dependencies []DependencyInfo `json:"dependencies,omitempty"`
}

// ArtifactInfo represents an artifact in a module.
type ArtifactInfo struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256,omitempty"`
}

// DependencyInfo represents a dependency in a module.
type DependencyInfo struct {
	ID     string   `json:"id"`
	Scopes []string `json:"scopes,omitempty"`
}

// RemoteRepoCredentials represents credentials extracted from a remote repository configuration.
type RemoteRepoCredentials struct {
	Key      string `json:"key"`
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	HasCreds bool   `json:"hasCreds"`
}

// LDAPConfig represents LDAP settings from system configuration
type LDAPConfig struct {
	XMLName  struct{} `xml:"config"`
	Security struct {
		LdapSettings struct {
			Settings []LDAPSetting `xml:"ldapSetting"`
		} `xml:"ldapSettings"`
	} `xml:"security"`
}

// LDAPSetting represents a single LDAP configuration
type LDAPSetting struct {
	Key           string `xml:"key" json:"key"`
	LdapUrl       string `xml:"ldapUrl" json:"ldapUrl"`
	UserDnPattern string `xml:"userDnPattern" json:"userDnPattern"`
	SearchBase    string `xml:"searchBase" json:"searchBase,omitempty"`
	ManagerDn     string `xml:"managerDn" json:"managerDn,omitempty"`
}

// BuildSecret represents a detected secret in a build
type BuildSecret struct {
	BuildName   string   `json:"buildName"`
	BuildNumber string   `json:"buildNumber"`
	EnvVar      string   `json:"envVar"`
	Value       string   `json:"value"`
	SecretTypes []string `json:"secretTypes"`
}

// JFrogMLSecret represents a secret stored in JFrog ML Secret Management
type JFrogMLSecret struct {
	Name          string `json:"name"`
	Value         string `json:"value,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
	CreatedAt     int64  `json:"created_at,omitempty"`
	LastUpdatedAt int64  `json:"last_updated_at,omitempty"`
	Error         string `json:"error,omitempty"`
}
