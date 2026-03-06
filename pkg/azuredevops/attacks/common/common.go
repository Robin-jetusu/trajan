package common

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// FindingHasType checks if any finding matches the given type.
// Delegates to detections.FindingHasType.
func FindingHasType(findings []detections.Finding, vulnType detections.VulnerabilityType) bool {
	return detections.FindingHasType(findings, vulnType)
}

// GetADOClient extracts Azure DevOps client from platform interface
func GetADOClient(platform platforms.Platform) (*azuredevops.Client, error) {
	adoPlatform, ok := platform.(*azuredevops.Platform)
	if !ok {
		return nil, fmt.Errorf("platform is not Azure DevOps")
	}
	return adoPlatform.Client(), nil
}

// ParseProjectRepo parses "project/repo" format into separate components
func ParseProjectRepo(target string) (string, string, error) {
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid target format, expected 'project/repo', got '%s'", target)
	}
	return parts[0], parts[1], nil
}

// AuthorizeVariableGroups authorizes a pipeline to access all provided variable groups
// This bypasses the "Waiting for review - Permission needed" block in Azure DevOps
func AuthorizeVariableGroups(ctx context.Context, client *azuredevops.Client, project string, pipelineID int, groups []azuredevops.VariableGroup) error {
	for _, group := range groups {
		if err := client.AuthorizePipelineResource(ctx, project, "variablegroup", group.ID, pipelineID); err != nil {
			// Non-fatal: log warning and continue
			fmt.Printf("Warning: failed to authorize pipeline %d for variable group %d (%s): %v\n",
				pipelineID, group.ID, group.Name, err)
			continue
		}
	}
	return nil
}
