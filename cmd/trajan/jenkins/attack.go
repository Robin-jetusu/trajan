package jenkins

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/platforms"

	// Import to trigger init() registration of Jenkins attack plugins
	_ "github.com/praetorian-inc/trajan/pkg/jenkins/attacks"
)

var (
	attackURL       string
	attackPlugin    string
	attackDryRun    bool
	attackConfirm   bool
	attackPayload   string
	attackCommand   string
	attackCleanup   bool
	attackTimeout   time.Duration
	attackSessionID string
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute attacks against Jenkins vulnerabilities",
	Long: `Trajan - Jenkins - Attack

Execute offensive operations against Jenkins CI/CD vulnerabilities.

SAFETY WARNING: This command executes real attacks. Always use --dry-run first.

Available Plugins:
  credential-dump    Dump Jenkins credentials via Groovy script console
  script-console     Execute arbitrary Groovy/OS commands
  job-injection      Create malicious job with shell command payload`,
	RunE: runAttack,
}

var attackCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up resources created by attacks",
	Long: `Trajan - Jenkins - Attack - Cleanup

Remove or revert resources created during attack execution.`,
	RunE: runAttackCleanup,
}

func init() {
	attackCmd.AddCommand(attackCleanupCmd)
	attackCleanupCmd.Flags().SortFlags = false
	attackCleanupCmd.Flags().Bool("list", false, "list available sessions")
	attackCleanupCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID to cleanup")
	attackCleanupCmd.Flags().StringVar(&attackURL, "url", "", "Jenkins instance URL")

	attackCmd.Flags().SortFlags = false
	attackCmd.Flags().StringVar(&attackURL, "url", "", "Jenkins instance URL")
	attackCmd.Flags().StringVar(&attackPlugin, "plugin", "", "attack plugin to run (credential-dump, script-console, job-injection)")
	attackCmd.Flags().BoolVar(&attackDryRun, "dry-run", false, "preview attack without executing")
	attackCmd.Flags().BoolVar(&attackConfirm, "confirm", false, "confirm live execution")
	attackCmd.Flags().StringVar(&attackPayload, "payload", "", "Groovy script payload")
	attackCmd.Flags().StringVar(&attackCommand, "command", "", "OS command to execute")
	attackCmd.Flags().BoolVar(&attackCleanup, "cleanup", false, "cleanup created resources after attack")
	attackCmd.Flags().DurationVar(&attackTimeout, "timeout", 5*time.Minute, "attack timeout")
	attackCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID for tracking")
}

func runAttack(cmd *cobra.Command, args []string) error {
	if !attackDryRun && !attackConfirm {
		return fmt.Errorf("SAFETY: Live attack execution requires --confirm flag.\nUse --dry-run to preview, or --confirm to execute")
	}

	if attackURL == "" {
		return fmt.Errorf("must specify --url")
	}

	if attackPlugin == "" {
		return fmt.Errorf("must specify --plugin (credential-dump, script-console, job-injection)")
	}

	token := getToken(cmd)
	username := getUsername(cmd)

	sessionID := attackSessionID
	if sessionID == "" {
		sessionID = uuid.New().String()[:8]
	}

	ctx, cancel := context.WithTimeout(context.Background(), attackTimeout)
	defer cancel()

	// Initialize platform
	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:   token,
		BaseURL: attackURL,
		Jenkins: &platforms.JenkinsAuth{Username: username},
	}
	cmdutil.ApplyProxyFlags(cmd, &config)

	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	// Get attack plugin
	plugin, err := registry.GetAttackPluginByName(registry.PluginKey(platforms.PlatformJenkins, attackPlugin))
	if err != nil {
		return fmt.Errorf("unknown plugin: %w", err)
	}

	// Build options
	extraOpts := make(map[string]string)
	if attackCommand != "" {
		extraOpts["command"] = attackCommand
	}
	if attackCleanup {
		extraOpts["cleanup"] = "true"
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetOrg, Value: attackURL},
		Platform:  platform,
		DryRun:    attackDryRun,
		Verbose:   cmdutil.GetVerbose(cmd),
		Timeout:   attackTimeout,
		SessionID: sessionID,
		Payload:   attackPayload,
		ExtraOpts: extraOpts,
	}

	if cmdutil.GetVerbose(cmd) {
		fmt.Fprintf(os.Stderr, "Executing %s (session: %s)...\n", attackPlugin, sessionID)
	}

	result, err := plugin.Execute(ctx, opts)
	if err != nil {
		return fmt.Errorf("attack failed: %w", err)
	}

	// If --cleanup was requested, report the inline cleanup result
	if attackCleanup {
		if len(result.CleanupActions) == 0 {
			// Cleanup succeeded (plugin cleared CleanupActions)
			result.Artifacts = nil // Clear artifacts so footer doesn't show
			fmt.Fprintf(os.Stderr, "Cleanup: successfully cleaned up resources\n")
		} else {
			// Cleanup failed — plugin left CleanupActions intact
			fmt.Fprintf(os.Stderr, "Cleanup: automatic cleanup failed, use manual cleanup command\n")
		}
	}

	// Create session and track (only needed if cleanup didn't happen or failed)
	if !attackCleanup || len(result.CleanupActions) > 0 {
		session := attacks.NewSession(sessionID, opts.Target, "jenkins", "")
		session.AddResult(result)
		if err := session.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
		}
	}

	// Output
	cleanupHint := "trajan jenkins attack cleanup --url <URL> --username <USER> --password <PASSWORD>"

	return cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), []*attacks.AttackResult{result}, sessionID, cleanupHint)
}

func runAttackCleanup(cmd *cobra.Command, args []string) error {
	list, _ := cmd.Flags().GetBool("list")
	if list {
		sessions, err := attacks.ListSessions()
		if err != nil {
			return fmt.Errorf("listing sessions: %w", err)
		}
		if len(sessions) == 0 {
			fmt.Println("No sessions found.")
			return nil
		}
		fmt.Println("=== Available Sessions ===")
		for _, s := range sessions {
			platformInfo := ""
			if s.PlatformName != "" {
				platformInfo = fmt.Sprintf(" [%s]", s.PlatformName)
			}
			fmt.Printf("  %s - %s%s (%d artifacts)\n", s.ID, s.Target.Value, platformInfo, s.ArtifactCount)
		}
		return nil
	}

	if attackSessionID == "" {
		return fmt.Errorf("must specify --session <id>, --session all, or --list")
	}

	// Handle --session all: clean up every saved session
	if attackSessionID == "all" {
		sessions, err := attacks.ListSessions()
		if err != nil {
			return fmt.Errorf("listing sessions: %w", err)
		}
		if len(sessions) == 0 {
			fmt.Println("No sessions to clean up.")
			return nil
		}

		// Initialize platform once if URL provided (needed for artifact cleanup)
		var platform platforms.Platform
		if attackURL != "" {
			ctx := context.Background()
			token := getToken(cmd)
			username := getUsername(cmd)

			p, err := registry.GetPlatform("jenkins")
			if err != nil {
				return fmt.Errorf("getting platform: %w", err)
			}
			config := platforms.Config{
				Token:   token,
				BaseURL: attackURL,
				Jenkins: &platforms.JenkinsAuth{Username: username},
			}
			cmdutil.ApplyProxyFlags(cmd, &config)
			if err := p.Init(ctx, config); err != nil {
				return fmt.Errorf("initializing platform: %w", err)
			}
			platform = p
		}

		fmt.Printf("=== Cleaning up all %d sessions ===\n", len(sessions))
		cleaned := 0
		failed := 0
		for _, s := range sessions {
			session, err := attacks.LoadSession(s.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %s: failed to load: %v\n", s.ID, err)
				failed++
				continue
			}

			// If session has artifacts that need cleanup, require platform
			if s.ArtifactCount > 0 {
				if platform == nil {
					fmt.Fprintf(os.Stderr, "  %s: has %d artifacts, skipping (specify --url for artifact cleanup)\n", s.ID, s.ArtifactCount)
					failed++
					continue
				}
				session.Platform = platform
				ctx := context.Background()
				for _, result := range session.Results {
					plugin, pErr := registry.GetAttackPluginByName(registry.PluginKey(session.PlatformName, result.Plugin))
					if pErr != nil {
						continue
					}
					if cErr := plugin.Cleanup(ctx, session); cErr != nil {
						fmt.Fprintf(os.Stderr, "  %s: cleanup %s failed: %v\n", s.ID, result.Plugin, cErr)
					}
				}
			}

			if err := session.Delete(); err != nil {
				fmt.Fprintf(os.Stderr, "  %s: failed to delete session file: %v\n", s.ID, err)
				failed++
			} else {
				cleaned++
			}
		}

		fmt.Printf("Cleaned up %d sessions", cleaned)
		if failed > 0 {
			fmt.Printf(" (%d failed)", failed)
		}
		fmt.Println()
		return nil
	}

	session, err := attacks.LoadSession(attackSessionID)
	if err != nil {
		return fmt.Errorf("loading session: %w", err)
	}

	ctx := context.Background()
	token := getToken(cmd)
	username := getUsername(cmd)

	if attackURL == "" {
		return fmt.Errorf("must specify --url for cleanup")
	}

	platform, err := registry.GetPlatform("jenkins")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	config := platforms.Config{
		Token:   token,
		BaseURL: attackURL,
		Jenkins: &platforms.JenkinsAuth{Username: username},
	}
	cmdutil.ApplyProxyFlags(cmd, &config)
	if err := platform.Init(ctx, config); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	session.Platform = platform

	fmt.Printf("=== Cleaning up session %s ===\n", attackSessionID)
	cleanedPlugins := make(map[string]bool)
	for _, result := range session.Results {
		if cleanedPlugins[result.Plugin] {
			continue
		}
		cleanedPlugins[result.Plugin] = true

		plugin, err := registry.GetAttackPluginByName(registry.PluginKey(session.PlatformName, result.Plugin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unknown plugin %s\n", result.Plugin)
			continue
		}

		fmt.Printf("Cleaning up %s...\n", result.Plugin)
		if err := plugin.Cleanup(ctx, session); err != nil {
			fmt.Fprintf(os.Stderr, "  Cleanup failed: %v\n", err)
		} else {
			fmt.Printf("  Cleaned up successfully\n")
		}
	}

	if err := session.Delete(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to delete session file: %v\n", err)
	}

	return nil
}
