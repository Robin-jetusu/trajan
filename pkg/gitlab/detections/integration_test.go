package detections

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// TestAllDetectionsRegistered verifies that all 8 expected GitLab detections are registered
func TestAllDetectionsRegistered(t *testing.T) {
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)
	require.GreaterOrEqual(t, len(dets), 7, "expected at least 7 GitLab detections")

	// Map detection names for easy lookup
	detectionNames := make(map[string]bool)
	for _, det := range dets {
		detectionNames[det.Name()] = true
	}

	// Verify all expected detections are registered
	expectedDetections := []string{
		"merge-request-unsafe-checkout",  // new
		"merge-request-secrets-exposure", // new
		"self-hosted-runner-exposure",    // new
		"script-injection",               // existing
		"unpinned-include",               // existing
		"include-injection",              // existing
		"token-exposure",                 // existing
	}

	for _, expected := range expectedDetections {
		assert.True(t, detectionNames[expected], "detection %s should be registered", expected)
	}
}

// TestAllDetectionsRunWithoutPanic ensures all detections can run without panicking
func TestAllDetectionsRunWithoutPanic(t *testing.T) {
	g := graph.NewGraph()
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request"})
	g.AddNode(wf)

	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)
	require.NotEmpty(t, dets, "No detections registered for GitLab platform")

	for _, det := range dets {
		t.Run(det.Name(), func(t *testing.T) {
			findings, err := det.Detect(ctx, g)
			assert.NoError(t, err, "Detection %s should not return error", det.Name())
			_ = findings // Findings may be empty for minimal graph, that's ok
		})
	}
}

// TestMultipleVulnerabilitiesDetected tests that multiple vulnerabilities
// can be detected simultaneously in a single workflow
func TestMultipleVulnerabilitiesDetected(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	// Workflow-level environment for secrets-exposure testing
	wf.Env = map[string]string{
		"API_KEY": "secret_value",
	}
	g.AddNode(wf)

	// Create job with self-hosted runner tag
	job := graph.NewJobNode("job1", "deploy", "")
	job.RunnerTags = []string{"self-hosted"}
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Step 1: Unsafe checkout of MR branch
	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	// Step 2: Execution that triggers pwnrequest
	step2 := graph.NewStepNode("step2", "install", 11)
	step2.Run = "npm install"
	step2.SetParent(job.ID())
	g.AddNode(step2)
	g.AddEdge(job.ID(), step2.ID(), graph.EdgeContains)

	// Step 3: Script injection vulnerability
	step3 := graph.NewStepNode("step3", "deploy", 12)
	step3.Run = "echo 'Deploying MR: $CI_MERGE_REQUEST_TITLE'"
	step3.SetParent(job.ID())
	g.AddNode(step3)
	g.AddEdge(job.ID(), step3.ID(), graph.EdgeContains)

	// Run all detections
	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err, "Detection %s should not error", det.Name())
		allFindings = append(allFindings, findings...)
	}

	// Verify we found multiple vulnerabilities
	require.NotEmpty(t, allFindings, "should detect at least one vulnerability")

	// Map findings by type
	findingsByType := make(map[detections.VulnerabilityType][]detections.Finding)
	for _, finding := range allFindings {
		findingsByType[finding.Type] = append(findingsByType[finding.Type], finding)
	}

	// Verify we detected expected vulnerability types
	// Note: Some detections may report the same VulnType but with different evidence

	// Should detect merge-request-unsafe-checkout (VulnMergeRequestUnsafeCheckout)
	assert.NotEmpty(t, findingsByType[detections.VulnMergeRequestUnsafeCheckout],
		"should detect unsafe checkout vulnerability")

	// Should detect script-injection (VulnScriptInjection)
	assert.NotEmpty(t, findingsByType[detections.VulnScriptInjection],
		"should detect script injection")

	// Should detect self-hosted-runner-exposure (VulnSelfHostedRunner)
	assert.NotEmpty(t, findingsByType[detections.VulnSelfHostedRunner],
		"should detect self-hosted runner exposure")
}

// TestCriticalFindingPresent verifies that at least one CRITICAL severity finding
// is detected in a vulnerable workflow
func TestCriticalFindingPresent(t *testing.T) {
	g := graph.NewGraph()

	// Create workflow with merge_request trigger
	wf := graph.NewWorkflowNode("wf1", "test", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	wf.AddTag(graph.TagMergeRequest)
	g.AddNode(wf)

	// Create job
	job := graph.NewJobNode("job1", "test", "")
	job.SetParent(wf.ID())
	g.AddNode(job)
	g.AddEdge(wf.ID(), job.ID(), graph.EdgeContains)

	// Create unsafe checkout pattern (should be CRITICAL)
	step1 := graph.NewStepNode("step1", "checkout", 10)
	step1.Run = "git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA && npm install"
	step1.SetParent(job.ID())
	g.AddNode(step1)
	g.AddEdge(job.ID(), step1.ID(), graph.EdgeContains)

	// Run all detections
	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	// Verify at least one CRITICAL finding
	hasCritical := false
	for _, finding := range allFindings {
		if finding.Severity == detections.SeverityCritical {
			hasCritical = true
			break
		}
	}

	assert.True(t, hasCritical, "expected at least one CRITICAL severity finding")
}

// TestDetectionWithIncludedWorkflows verifies that detections work correctly on included workflow files.
// This test ensures that:
// 1. Vulnerabilities in included files are detected
// 2. Findings reference the correct source file path
func TestDetectionWithIncludedWorkflows(t *testing.T) {
	g := graph.NewGraph()

	// Create main workflow with merge_request trigger
	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	// Create included workflow with a script injection vulnerability
	includedWf := graph.NewWorkflowNode("wf:included:build", "build", ".gitlab/ci/build.yml", "test/repo", []string{"merge_request_event"})
	includedWf.AddTag(graph.TagMergeRequest)
	g.AddNode(includedWf)

	// Add EdgeIncludes edge from main to included workflow
	g.AddEdge(mainWf.ID(), includedWf.ID(), graph.EdgeIncludes)

	// Create job in the included workflow
	job := graph.NewJobNode("wf:included:build:job:deploy", "deploy", "")
	job.SetParent(includedWf.ID())
	g.AddNode(job)
	g.AddEdge(includedWf.ID(), job.ID(), graph.EdgeContains)

	// Create step with script injection vulnerability
	step := graph.NewStepNode("wf:included:build:job:deploy:step:0", "deploy", 10)
	step.Run = "echo 'Deploying MR: $CI_MERGE_REQUEST_TITLE'"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	// Run all detections
	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err, "Detection %s should not error", det.Name())
		allFindings = append(allFindings, findings...)
	}

	// Verify that we detected the script injection
	scriptInjectionFindings := []detections.Finding{}
	for _, finding := range allFindings {
		if finding.Type == detections.VulnScriptInjection {
			scriptInjectionFindings = append(scriptInjectionFindings, finding)
		}
	}

	require.NotEmpty(t, scriptInjectionFindings, "should detect script injection in included workflow")

	// Verify that the finding references the correct source file
	foundCorrectSource := false
	for _, finding := range scriptInjectionFindings {
		if finding.Workflow == ".gitlab/ci/build.yml" {
			foundCorrectSource = true
			// Also verify other expected fields
			assert.Equal(t, "test/repo", finding.Repository)
			assert.Equal(t, "deploy", finding.Step)
			assert.Equal(t, 10, finding.Line)
			assert.Contains(t, finding.Evidence, "CI_MERGE_REQUEST_TITLE")
			break
		}
	}

	assert.True(t, foundCorrectSource, "finding should reference the included workflow file path (.gitlab/ci/build.yml)")
}

// TestDetectionWithMultipleIncludes verifies that detections work correctly when
// multiple workflow files are included and contain vulnerabilities in different files.
func TestDetectionWithMultipleIncludes(t *testing.T) {
	g := graph.NewGraph()

	// Create main workflow
	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	// Create first included workflow with script injection
	buildWf := graph.NewWorkflowNode("wf:included:build", "build", ".gitlab/ci/build.yml", "test/repo", []string{"merge_request_event"})
	buildWf.AddTag(graph.TagMergeRequest)
	g.AddNode(buildWf)
	g.AddEdge(mainWf.ID(), buildWf.ID(), graph.EdgeIncludes)

	// Create second included workflow with self-hosted runner exposure
	testWf := graph.NewWorkflowNode("wf:included:test", "test", ".gitlab/ci/test.yml", "test/repo", []string{"merge_request_event"})
	testWf.AddTag(graph.TagMergeRequest)
	g.AddNode(testWf)
	g.AddEdge(mainWf.ID(), testWf.ID(), graph.EdgeIncludes)

	// Job in build.yml with script injection
	buildJob := graph.NewJobNode("wf:included:build:job:build", "build", "")
	buildJob.SetParent(buildWf.ID())
	g.AddNode(buildJob)
	g.AddEdge(buildWf.ID(), buildJob.ID(), graph.EdgeContains)

	buildStep := graph.NewStepNode("wf:included:build:job:build:step:0", "build", 5)
	buildStep.Run = "echo $CI_MERGE_REQUEST_TITLE"
	buildStep.SetParent(buildJob.ID())
	g.AddNode(buildStep)
	g.AddEdge(buildJob.ID(), buildStep.ID(), graph.EdgeContains)

	// Job in test.yml with self-hosted runner
	testJob := graph.NewJobNode("wf:included:test:job:test", "test", "")
	testJob.RunnerTags = []string{"self-hosted"}
	testJob.SetParent(testWf.ID())
	g.AddNode(testJob)
	g.AddEdge(testWf.ID(), testJob.ID(), graph.EdgeContains)

	testStep := graph.NewStepNode("wf:included:test:job:test:step:0", "test", 8)
	testStep.Run = "npm test"
	testStep.SetParent(testJob.ID())
	g.AddNode(testStep)
	g.AddEdge(testJob.ID(), testStep.ID(), graph.EdgeContains)

	// Run all detections
	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	// Verify we detected vulnerabilities in both files
	findingsByWorkflow := make(map[string][]detections.Finding)
	for _, finding := range allFindings {
		findingsByWorkflow[finding.Workflow] = append(findingsByWorkflow[finding.Workflow], finding)
	}

	// Check for script injection in build.yml
	buildFindings := findingsByWorkflow[".gitlab/ci/build.yml"]
	hasScriptInjection := false
	for _, f := range buildFindings {
		if f.Type == detections.VulnScriptInjection {
			hasScriptInjection = true
			assert.Equal(t, 5, f.Line, "should reference correct line in build.yml")
			break
		}
	}
	assert.True(t, hasScriptInjection, "should detect script injection in build.yml")

	// Check for self-hosted runner in test.yml
	testFindings := findingsByWorkflow[".gitlab/ci/test.yml"]
	hasSelfHosted := false
	for _, f := range testFindings {
		if f.Type == detections.VulnSelfHostedRunner {
			hasSelfHosted = true
			assert.Contains(t, f.Evidence, "self-hosted", "should mention self-hosted runner")
			break
		}
	}
	assert.True(t, hasSelfHosted, "should detect self-hosted runner in test.yml")
}

// TestDetectionWithNestedIncludes verifies that detections work correctly with
// nested includes (include within include).
func TestDetectionWithNestedIncludes(t *testing.T) {
	g := graph.NewGraph()

	// Create main workflow
	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	// Create first-level included workflow
	level1Wf := graph.NewWorkflowNode("wf:included:level1", "level1", ".gitlab/ci/level1.yml", "test/repo", []string{"merge_request_event"})
	level1Wf.AddTag(graph.TagMergeRequest)
	g.AddNode(level1Wf)
	g.AddEdge(mainWf.ID(), level1Wf.ID(), graph.EdgeIncludes)

	// Create second-level nested included workflow
	level2Wf := graph.NewWorkflowNode("wf:included:level1:included:level2", "level2", ".gitlab/ci/nested/level2.yml", "test/repo", []string{"merge_request_event"})
	level2Wf.AddTag(graph.TagMergeRequest)
	g.AddNode(level2Wf)
	g.AddEdge(level1Wf.ID(), level2Wf.ID(), graph.EdgeIncludes)

	// Job in nested workflow with vulnerability
	job := graph.NewJobNode("wf:included:level1:included:level2:job:deploy", "deploy", "")
	job.SetParent(level2Wf.ID())
	g.AddNode(job)
	g.AddEdge(level2Wf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("wf:included:level1:included:level2:job:deploy:step:0", "deploy", 12)
	step.Run = "deploy.sh $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	// Run all detections
	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	// Verify we detected the vulnerability in the nested include
	foundInNestedFile := false
	for _, finding := range allFindings {
		if finding.Type == detections.VulnScriptInjection &&
			finding.Workflow == ".gitlab/ci/nested/level2.yml" {
			foundInNestedFile = true
			assert.Equal(t, 12, finding.Line)
			assert.Contains(t, finding.Evidence, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
			break
		}
	}

	assert.True(t, foundInNestedFile, "should detect vulnerability in nested included workflow file")
}

// TestDetectionWithIncludesNoVulnerability verifies that detections don't produce
// false positives when included files are safe.
func TestDetectionWithIncludesNoVulnerability(t *testing.T) {
	g := graph.NewGraph()

	// Create main workflow
	mainWf := graph.NewWorkflowNode("wf:main", "main", ".gitlab-ci.yml", "test/repo", []string{"merge_request_event"})
	mainWf.AddTag(graph.TagMergeRequest)
	g.AddNode(mainWf)

	// Create included workflow with safe script
	includedWf := graph.NewWorkflowNode("wf:included:safe", "safe", ".gitlab/ci/safe.yml", "test/repo", []string{"merge_request_event"})
	includedWf.AddTag(graph.TagMergeRequest)
	g.AddNode(includedWf)
	g.AddEdge(mainWf.ID(), includedWf.ID(), graph.EdgeIncludes)

	// Job with safe script (no injectable variables)
	job := graph.NewJobNode("wf:included:safe:job:test", "test", "")
	job.SetParent(includedWf.ID())
	g.AddNode(job)
	g.AddEdge(includedWf.ID(), job.ID(), graph.EdgeContains)

	step := graph.NewStepNode("wf:included:safe:job:test:step:0", "test", 5)
	step.Run = "npm test"
	step.SetParent(job.ID())
	g.AddNode(step)
	g.AddEdge(job.ID(), step.ID(), graph.EdgeContains)

	// Run all detections
	ctx := context.Background()
	dets := registry.GetDetectionsForPlatform(platforms.PlatformGitLab)

	allFindings := []detections.Finding{}
	for _, det := range dets {
		findings, err := det.Detect(ctx, g)
		require.NoError(t, err)
		allFindings = append(allFindings, findings...)
	}

	// Verify no script injection findings for the safe included file
	for _, finding := range allFindings {
		if finding.Workflow == ".gitlab/ci/safe.yml" && finding.Type == detections.VulnScriptInjection {
			t.Errorf("unexpected script injection finding in safe included workflow: %+v", finding)
		}
	}
}
