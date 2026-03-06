// pkg/platforms/azuredevops/types_extended_test.go
package azuredevops

import "testing"

func TestBuildNamespaceID(t *testing.T) {
	// Verified against Microsoft official documentation
	// https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference
	expected := "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
	if BuildNamespaceID != expected {
		t.Errorf("BuildNamespaceID = %q, want %q", BuildNamespaceID, expected)
	}
}

func TestBuildPermissionBits(t *testing.T) {
	// Verified against Microsoft official documentation
	// https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference#build
	expected := map[int]string{
		1:     "ViewBuilds",
		2:     "EditBuildQuality",
		4:     "RetainIndefinitely",
		8:     "DeleteBuilds",
		16:    "ManageBuildQualities",
		32:    "DestroyBuilds",
		64:    "UpdateBuildInformation",
		128:   "QueueBuilds",
		256:   "ManageBuildQueue",
		512:   "StopBuilds",
		1024:  "ViewBuildDefinition",
		2048:  "EditBuildDefinition",
		4096:  "DeleteBuildDefinition",
		8192:  "OverrideBuildCheckInValidation",
		16384: "AdministerBuildPermissions",
	}

	if len(BuildPermissionBits) != len(expected) {
		t.Errorf("BuildPermissionBits has %d entries, want %d", len(BuildPermissionBits), len(expected))
	}

	for bit, name := range expected {
		if actual, ok := BuildPermissionBits[bit]; !ok {
			t.Errorf("BuildPermissionBits missing bit %d (%s)", bit, name)
		} else if actual != name {
			t.Errorf("BuildPermissionBits[%d] = %q, want %q", bit, actual, name)
		}
	}
}

func TestGitPermissionBits(t *testing.T) {
	// Verified against Microsoft official documentation
	// https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference#git-repositories
	expected := map[int]string{
		1:     "Administer",
		2:     "GenericRead",
		4:     "GenericContribute",
		8:     "ForcePush",
		16:    "CreateBranch",
		32:    "CreateTag",
		64:    "ManageNote",
		128:   "PolicyExempt",
		256:   "CreateRepository",
		512:   "DeleteRepository",
		1024:  "RenameRepository",
		2048:  "EditPolicies",
		4096:  "RemoveOthersLocks",
		8192:  "ManagePermissions",
		16384: "PullRequestContribute",
		32768: "PullRequestBypassPolicy",
	}

	if len(GitPermissionBits) != len(expected) {
		t.Errorf("GitPermissionBits has %d entries, want %d", len(GitPermissionBits), len(expected))
	}

	for bit, name := range expected {
		if actual, ok := GitPermissionBits[bit]; !ok {
			t.Errorf("GitPermissionBits missing bit %d (%s)", bit, name)
		} else if actual != name {
			t.Errorf("GitPermissionBits[%d] = %q, want %q", bit, actual, name)
		}
	}
}
