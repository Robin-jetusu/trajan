package agentsecurity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestAgentSecurityDetection_Name(t *testing.T) {
	d := New()
	assert.Equal(t, "agent-security", d.Name())
}

func TestAgentSecurityDetection_Platform(t *testing.T) {
	d := New()
	assert.Equal(t, platforms.PlatformAzureDevOps, d.Platform())
}

func TestAgentSecurityDetection_Severity(t *testing.T) {
	d := New()
	assert.Equal(t, detections.SeverityHigh, d.Severity())
}

func TestAgentSecurityDetection_Detect_SelfHostedPool(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "deploy", "my-self-hosted-pool")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Expected to find self-hosted pool")

	finding := findings[0]
	assert.Equal(t, detections.VulnSelfHostedAgent, finding.Type)
	assert.Equal(t, detections.ClassRunnerSecurity, finding.Class)
	assert.Equal(t, platforms.PlatformAzureDevOps, finding.Platform)
}

func TestAgentSecurityDetection_Detect_UbuntuLatestSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for ubuntu-latest")
}

func TestAgentSecurityDetection_Detect_WindowsLatestSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "windows-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for windows-latest")
}

func TestAgentSecurityDetection_Detect_MacOSSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "macos-latest")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for macos-latest")
}

func TestAgentSecurityDetection_Detect_VMImageSafe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "vmimage:ubuntu-22.04")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for vmimage")
}

func TestAgentSecurityDetection_Detect_Ubuntu2204Safe(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "build", "ubuntu-22.04")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Empty(t, findings, "Expected no findings for ubuntu-22.04")
}

func TestAgentSecurityDetection_Detect_MultipleJobsMixed(t *testing.T) {
	d := New()
	ctx := context.Background()

	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "pipeline.yml", "pipeline.yml", "owner/repo", nil)
	g.AddNode(wf)

	// Safe job with ubuntu-latest
	job1 := graph.NewJobNode("job1", "build", "ubuntu-latest")
	job1.SetParent(wf.ID())
	g.AddNode(job1)
	g.AddEdge(wf.ID(), job1.ID(), graph.EdgeContains)

	// Unsafe job with self-hosted pool
	job2 := graph.NewJobNode("job2", "deploy", "custom-pool")
	job2.SetParent(wf.ID())
	g.AddNode(job2)
	g.AddEdge(wf.ID(), job2.ID(), graph.EdgeContains)

	findings, err := d.Detect(ctx, g)
	require.NoError(t, err)
	assert.Len(t, findings, 1, "Expected exactly 1 finding for self-hosted pool")
}
