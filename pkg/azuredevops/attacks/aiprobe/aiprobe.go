package aiprobe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	sharedaiprobe "github.com/praetorian-inc/trajan/pkg/attacks/shared/aiprobe"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-ai-probe", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements AI service endpoint probing for Azure DevOps repositories.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new AI probe attack plugin for Azure DevOps.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-ai-probe",
			"Probe AI service endpoints discovered in Azure DevOps pipelines",
			"azuredevops",
			attacks.CategoryRecon,
		),
	}
}

// knownPipelinePaths lists standard Azure DevOps pipeline YAML locations.
var knownPipelinePaths = []string{
	"azure-pipelines.yml",
	".azure-pipelines/azure-pipelines.yml",
	".azure-pipelines/ci.yml",
	".azure-pipelines/cd.yml",
}

// aiVulnTypes lists all AI-related vulnerability types that trigger this plugin.
var aiVulnTypes = detections.AIVulnTypes

// CanAttack returns true if any AI-related vulnerability was found.
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	for _, vt := range aiVulnTypes {
		if common.FindingHasType(findings, vt) {
			return true
		}
	}
	return false
}

// Execute fetches pipeline YAML, extracts AI endpoints, and probes them with Julius.
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}
	defer func() {
		audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	}()

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, fmt.Errorf("invalid platform type")
	}

	// Parse project/repo
	project, repo, err := common.ParseProjectRepo(opts.Target.Value)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Get repository (needed for default branch and repo ID)
	repository, err := client.GetRepository(ctx, project, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to get repository: %v", err)
		return result, err
	}
	defaultBranch := repository.DefaultBranch
	if defaultBranch == "" {
		defaultBranch = "refs/heads/main"
	}
	defaultBranch = strings.TrimPrefix(defaultBranch, "refs/heads/")

	// Discover pipeline YAML paths from build definitions, fall back to known paths
	yamlPaths := discoverPipelinePaths(ctx, client, project, repository.ID)

	// Fetch and extract endpoints from each pipeline file
	var allEndpoints []sharedaiprobe.DiscoveredEndpoint
	filesFound := 0
	for _, yamlPath := range yamlPaths {
		content, err := client.GetWorkflowFile(ctx, project, repo, yamlPath, defaultBranch)
		if err != nil {
			continue
		}
		filesFound++
		endpoints := sharedaiprobe.ExtractEndpoints(content, yamlPath)
		allEndpoints = append(allEndpoints, endpoints...)
	}
	allEndpoints = sharedaiprobe.DeduplicateEndpoints(allEndpoints)

	// Dry run: return discovered endpoints without probing
	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Discovered %d AI service endpoint(s) across %d pipeline file(s)", len(allEndpoints), filesFound)
		result.Data = &sharedaiprobe.ScanResults{
			Endpoints: allEndpoints,
			Summary: sharedaiprobe.ScanSummary{
				EndpointsDiscovered: len(allEndpoints),
			},
		}
		return result, nil
	}

	// Probe endpoints with Julius
	scanConfig := sharedaiprobe.DefaultScanConfig()
	scanResults, err := sharedaiprobe.ProbeEndpoints(ctx, allEndpoints, scanConfig)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("probe failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("Probed %d endpoint(s): %d reachable, %d service(s) identified",
		scanResults.Summary.EndpointsProbed,
		scanResults.Summary.EndpointsReachable,
		scanResults.Summary.ServicesIdentified)
	result.Data = scanResults

	return result, nil
}

// discoverPipelinePaths queries the build definitions API for registered pipeline
// YAML paths. Falls back to knownPipelinePaths if the API fails or returns nothing.
func discoverPipelinePaths(ctx context.Context, client *azuredevops.Client, project, repoID string) []string {
	defs, err := client.ListBuildDefinitionsByRepo(ctx, project, repoID)
	if err != nil || len(defs) == 0 {
		return knownPipelinePaths
	}

	seen := make(map[string]bool)
	var paths []string
	for _, def := range defs {
		fullDef, err := client.GetBuildDefinition(ctx, project, def.ID)
		if err != nil || fullDef.Process.YamlFilename == "" {
			continue
		}
		if !seen[fullDef.Process.YamlFilename] {
			seen[fullDef.Process.YamlFilename] = true
			paths = append(paths, fullDef.Process.YamlFilename)
		}
	}

	if len(paths) == 0 {
		return knownPipelinePaths
	}
	return paths
}

// Cleanup is a no-op — AI probing is read-only and creates no artifacts.
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	return nil
}
