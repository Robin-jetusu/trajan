package credentials

import (
	"context"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func TestNew(t *testing.T) {
	d := New()
	if d.Name() != "credentials" {
		t.Errorf("Name() = %q, want %q", d.Name(), "credentials")
	}
	if d.Platform() != "jenkins" {
		t.Errorf("Platform() = %q, want %q", d.Platform(), "jenkins")
	}
	if d.Severity() != detections.SeverityHigh {
		t.Errorf("Severity() = %q, want %q", d.Severity(), detections.SeverityHigh)
	}
}

func TestDetect_HardcodedPassword(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "linux")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "Deploy", 10)
	step.Run = `password = "SuperSecret123!"`
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(findings))
	}
	if findings[0].Type != detections.VulnHardcodedContainerCreds {
		t.Errorf("finding type = %q, want %q", findings[0].Type, detections.VulnHardcodedContainerCreds)
	}
	if findings[0].Platform != "jenkins" {
		t.Errorf("finding platform = %q, want %q", findings[0].Platform, "jenkins")
	}
}

func TestDetect_HardcodedApiKeyInEnv(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "linux")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "Call API", 20)
	step.Env = map[string]string{
		"API_KEY": `api_key = "abcdefghijklmnopqrstuvwxyz"`,
	}
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(findings))
	}
}

func TestDetect_SafeStep(t *testing.T) {
	d := New()
	g := graph.NewGraph()

	wf := graph.NewWorkflowNode("wf1", "Jenkinsfile", "Jenkinsfile", "org/repo", []string{"push"})
	g.AddNode(wf)

	job := graph.NewJobNode("job1", "Build", "linux")
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("step1", "Safe step", 5)
	step.Run = `echo "hello world"`
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	findings, err := d.Detect(context.Background(), g)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Detect() returned %d findings, want 0", len(findings))
	}
}
