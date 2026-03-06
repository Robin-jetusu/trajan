package detections

import (
	"testing"
)

func TestVulnerabilityTypesForPlatform_AzureDevOps(t *testing.T) {
	types := VulnerabilityTypesForPlatform("azuredevops")

	expected := []VulnerabilityType{
		VulnScriptInjection,
		VulnTriggerExploitation,
		VulnServiceConnectionHijacking,
		VulnDynamicTemplateInjection,
		VulnExcessiveJobPermissions,
		VulnOverexposedServiceConnections,
		VulnSecretScopeRisk,
		VulnEnvironmentBypass,
		VulnSelfHostedAgent,
		VulnAITokenExfiltration,
		VulnAICodeInjection,
		VulnAIMCPAbuse,
		VulnAIWorkflowSabotage,
		VulnAIPrivilegeEscalation,
		VulnAISupplyChainPoisoning,
		VulnUnredactedSecrets,
		VulnTokenExposure,
		VulnPullRequestSecretsExposure,
	}

	if len(types) != len(expected) {
		t.Fatalf("VulnerabilityTypesForPlatform(\"azuredevops\") returned %d types, want %d", len(types), len(expected))
	}

	expectedSet := make(map[VulnerabilityType]bool, len(expected))
	for _, e := range expected {
		expectedSet[e] = true
	}

	for _, typ := range types {
		if !expectedSet[typ] {
			t.Errorf("unexpected type %q in azuredevops platform types", typ)
		}
	}
}

func TestVulnerabilityTypesForPlatform_UnknownFallsBackToAll(t *testing.T) {
	types := VulnerabilityTypesForPlatform("unknown_platform")
	if len(types) != len(AllVulnerabilityTypes) {
		t.Errorf("unknown platform returned %d types, want %d (AllVulnerabilityTypes)", len(types), len(AllVulnerabilityTypes))
	}
}

func TestVulnerabilityTypesForPlatform_EmptyFallsBackToAll(t *testing.T) {
	types := VulnerabilityTypesForPlatform("")
	if len(types) != len(AllVulnerabilityTypes) {
		t.Errorf("empty platform returned %d types, want %d (AllVulnerabilityTypes)", len(types), len(AllVulnerabilityTypes))
	}
}
