package aiprobe

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	sharedaiprobe "github.com/praetorian-inc/trajan/pkg/attacks/shared/aiprobe"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/github/attacks/common"
)

func init() {
	registry.RegisterAttackPlugin("github", "ai-probe", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements AI service endpoint probing for GitHub repositories.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new AI probe attack plugin for GitHub.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ai-probe",
			"Probe AI service endpoints discovered in GitHub Actions workflows",
			"github",
			attacks.CategoryRecon,
		),
	}
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

// Execute fetches workflow YAML, extracts AI endpoints, and probes them with Julius.
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

	// Get GitHub client
	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}
	client := ghPlatform.Client()

	// Parse owner/repo
	owner, repo, err := common.ParseOwnerRepo(opts.Target)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Fetch workflow file listing
	workflowFiles, err := client.GetWorkflowFiles(ctx, owner, repo)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to list workflow files: %v", err)
		return result, err
	}

	// Extract endpoints from each workflow file
	var allEndpoints []sharedaiprobe.DiscoveredEndpoint
	for _, wf := range workflowFiles {
		content, err := client.GetWorkflowContent(ctx, owner, repo, wf.Path)
		if err != nil {
			continue
		}
		endpoints := sharedaiprobe.ExtractEndpoints(content, wf.Path)
		allEndpoints = append(allEndpoints, endpoints...)
	}
	allEndpoints = sharedaiprobe.DeduplicateEndpoints(allEndpoints)

	// Dry run: return discovered endpoints without probing
	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Discovered %d AI service endpoint(s) across %d workflow(s)", len(allEndpoints), len(workflowFiles))
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

// Cleanup is a no-op — AI probing is read-only and creates no artifacts.
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	return nil
}
