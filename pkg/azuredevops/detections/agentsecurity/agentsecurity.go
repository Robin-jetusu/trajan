package agentsecurity

import (
	"context"
	"strings"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/base"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterDetection(platforms.PlatformAzureDevOps, "agent-security", func() detections.Detection {
		return New()
	})
}

// Detection detects agent security issues such as use of self-hosted agent pools
type Detection struct {
	base.BaseDetection
}

// New creates a new agent-security detection
func New() *Detection {
	return &Detection{
		BaseDetection: base.NewBaseDetection("agent-security", platforms.PlatformAzureDevOps, detections.SeverityHigh),
	}
}

// Detect analyzes the graph for unrestricted self-hosted agent pools
func (d *Detection) Detect(ctx context.Context, g *graph.Graph) ([]detections.Finding, error) {
	var findings []detections.Finding

	// Get all workflow nodes
	workflows := g.GetNodesByType(graph.NodeTypeWorkflow)

	for _, wfNode := range workflows {
		wf := wfNode.(*graph.WorkflowNode)

		// DFS through all jobs to check agent pools
		graph.DFS(g, wf.ID(), func(node graph.Node) bool {
			if node.Type() == graph.NodeTypeJob {
				job := node.(*graph.JobNode)

				if isSelfHostedPool(job.RunsOn) {
					findings = append(findings, detections.Finding{
						Type:        detections.VulnSelfHostedAgent,
						Platform:    platforms.PlatformAzureDevOps,
						Class:       detections.ClassRunnerSecurity,
						Severity:    detections.SeverityHigh,
						Confidence:  detections.ConfidenceHigh,
						Complexity:  detections.ComplexityLow,
						Repository:  wf.RepoSlug,
						Workflow:    wf.Name,
						Job:         job.Name,
						Line:        job.Line,
						Evidence:    "Job uses self-hosted agent pool: " + job.RunsOn,
						Remediation: "Use Microsoft-hosted agents when possible. If self-hosted agents are required, ensure they are properly secured, isolated, and regularly updated. Review agent pool permissions and restrict access.",
						Details: &detections.FindingDetails{
							LineRanges: []detections.LineRange{{
								Start: job.Line,
								End:   job.Line,
								Label: "self-hosted agent pool",
							}},
						},
					})
				}
			}
			return true
		})
	}

	return findings, nil
}

// isSelfHostedPool checks if the RunsOn value indicates a self-hosted agent pool
func isSelfHostedPool(runsOn string) bool {
	// Empty RunsOn means no pool specified — uses project default, not definitively self-hosted
	if runsOn == "" {
		return false
	}

	runsOnLower := strings.ToLower(runsOn)

	// Microsoft-hosted pools (safe)
	microsoftHostedPools := []string{
		"ubuntu-latest",
		"ubuntu-24.04",
		"ubuntu-22.04",
		"ubuntu-20.04",
		"windows-latest",
		"windows-2025",
		"windows-2022",
		"windows-2019",
		"macos-latest",
		"macos-15",
		"macos-14",
		"macos-13",
		"macos-12",
		"azure pipelines",
		"vmimage:",
	}

	for _, hostedPool := range microsoftHostedPools {
		if strings.Contains(runsOnLower, hostedPool) {
			return false
		}
	}

	// If it doesn't match any Microsoft-hosted pool, it's self-hosted
	return true
}
