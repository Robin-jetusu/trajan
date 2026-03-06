package common

// PredefinedGroups maps friendly names to Azure DevOps group display names
var PredefinedGroups = map[string]string{
	"project-admin":          "Project Administrators",
	"build-admin":            "Build Administrators",
	"collection-admin":       "Project Collection Administrators",
	"collection-build-admin": "Project Collection Build Administrators",
	"collection-build-svc":   "Project Collection Build Service Accounts",
	"collection-svc":         "Project Collection Service Accounts",
}

// ResolveGroupName resolves a friendly group name to the Azure DevOps display name
func ResolveGroupName(friendlyName string) (string, bool) {
	name, ok := PredefinedGroups[friendlyName]
	return name, ok
}
