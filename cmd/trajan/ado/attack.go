package ado

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"

	_ "github.com/praetorian-inc/trajan/pkg/attacks/all"
)

var (
	// Attack target flags
	attackRepo string
	attackOrg  string

	// Attack selection flags
	attackPlugins  []string
	attackCategory string
	attackAll      bool

	// Execution flags
	attackDryRun    bool
	attackConfirm   bool
	attackForce     bool
	attackTimeout   time.Duration
	attackSessionID string

	// Azure DevOps attack-specific flags
	attackGroup          string
	attackConnection     string
	attackConnectionType string
	attackSecureFile     string
	attackUserDescriptor string

	// Output flags
	attackOutputFile string

	attackPool    string
	attackCommand string

	// Persistence flags
	attackMethod    string
	attackPublicKey string
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute attacks against Azure DevOps CI/CD vulnerabilities",
	Long: `Trajan - Azure DevOps - Attack

Execute offensive operations against detected Azure DevOps CI/CD vulnerabilities.

SAFETY WARNING: This command executes real attacks that modify resources.
Always use --dry-run first to preview changes.

Available Plugins:
  ado-secrets-dump        Dump all secrets (env vars + variable groups), or target a specific group with --group
  ado-pipeline-injection  Inject into pipelines via poisoned pipeline execution (PPE)
  ado-pr-attack           PR-based pipeline execution attack
  ado-extract-connections Extract service connection credentials
  ado-extract-securefiles Download secure files
  ado-privesc             Privilege escalation in Azure DevOps
  ado-persistence         Establish persistent access via PAT or SSH key creation
                          NOTE: Requires --azure-bearer-token (Entra ID). PATs cannot
                          create other PATs or SSH keys — Azure DevOps rejects these
                          requests with 401 when authenticated via PAT.
  ado-agent-exec          Execute commands on self-hosted agents
  ado-ai-probe            Probe AI/ML service endpoints for token exfiltration

Categories: secrets, cicd, runners, persistence, c2`,
	RunE: runAttack,
}

var attackCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up resources created by attacks",
	Long: `Trajan - Azure DevOps - Attack

Remove or revert resources created during attack execution.
Looks up the session by ID and calls each plugin's cleanup handler to undo changes.
Use --list to show available sessions, or --session <id> to clean up a specific session.`,
	RunE: runAttackCleanup,
}

func init() {
	attackCmd.AddCommand(attackCleanupCmd)

	attackCmd.Flags().SortFlags = false

	// Target flags
	attackCmd.Flags().StringVar(&attackRepo, "repo", "", "repository to attack (project/repo)")
	attackCmd.Flags().StringVar(&attackOrg, "org", "", "Azure DevOps organization name or URL")

	// Attack selection
	attackCmd.Flags().StringSliceVar(&attackPlugins, "plugin", nil, "attack plugins to run (comma-separated)")
	attackCmd.Flags().StringVar(&attackCategory, "category", "", "attack category filter (secrets, cicd, runners, persistence, c2)")
	attackCmd.Flags().BoolVar(&attackAll, "all", false, "run all applicable attacks")

	// Execution control
	attackCmd.Flags().BoolVar(&attackDryRun, "dry-run", false, "preview attack without executing")
	attackCmd.Flags().BoolVar(&attackConfirm, "confirm", false, "confirm live execution (required without --dry-run)")
	attackCmd.Flags().BoolVar(&attackForce, "force", false, "bypass vulnerability check for attack plugins (force execution)")
	attackCmd.Flags().DurationVar(&attackTimeout, "timeout", 5*time.Minute, "attack timeout")
	attackCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID for tracking/cleanup")

	// Azure DevOps attack-specific flags
	attackCmd.Flags().StringVar(&attackGroup, "group", "", "variable group name (for ado-secrets-dump, targets specific group)")
	attackCmd.Flags().StringVar(&attackConnection, "connection", "", "service connection name (for ado-extract-connections)")
	attackCmd.Flags().StringVar(&attackConnectionType, "connection-type", "", "service connection type: azure, github, aws, kubernetes, docker, ssh, sonarqube (for ado-extract-connections)")
	attackCmd.Flags().StringVar(&attackSecureFile, "secure-file", "", "secure file name (for ado-extract-securefiles)")
	attackCmd.Flags().StringVar(&attackUserDescriptor, "user-descriptor", "", "user descriptor to escalate (for ado-privesc)")
	attackCmd.Flags().StringVar(&attackPool, "pool", "", "self-hosted agent pool name (for ado-agent-exec)")
	attackCmd.Flags().StringVar(&attackCommand, "command", "", "command to execute on self-hosted agent (for ado-agent-exec)")
	attackCmd.Flags().StringVar(&attackMethod, "method", "", "persistence method: pat or ssh (for ado-persistence, default: pat)")
	attackCmd.Flags().StringVar(&attackPublicKey, "public-key", "", "path to SSH public key file (for ado-persistence --method ssh)")

	// Output flags
	attackCmd.Flags().StringVar(&attackOutputFile, "output-file", "", "write extracted secrets/output to file")

	// Cleanup flags
	attackCleanupCmd.Flags().SortFlags = false
	attackCleanupCmd.Flags().StringVar(&attackSessionID, "session", "", "session ID to cleanup")
	attackCleanupCmd.Flags().Bool("list", false, "list available sessions")
	attackCleanupCmd.Flags().StringVar(&attackOrg, "org", "", "organization (auto-detected from session if not specified)")
}

func runAttack(cmd *cobra.Command, args []string) error {
	if !attackDryRun && !attackConfirm {
		return fmt.Errorf("SAFETY: Live attack execution requires --confirm flag.\n" +
			"Use --dry-run to preview, or --confirm to execute.\n" +
			"Example: trajan ado attack --repo project/repo --plugin ado-secrets-dump --confirm")
	}

	if len(attackPlugins) == 0 && attackCategory == "" && !attackAll {
		return fmt.Errorf("must specify --plugin, --category, or --all to select attacks\n" +
			"Example: trajan ado attack --repo project/repo --plugin ado-secrets-dump --confirm")
	}

	t := getToken(cmd)
	bt := getBearerToken(cmd)
	if t == "" && bt == "" {
		return fmt.Errorf("no token provided (use --token, --azure-bearer-token, or set AZURE_DEVOPS_PAT/AZURE_BEARER_TOKEN)")
	}

	var target platforms.Target
	switch {
	case attackRepo != "":
		target = platforms.Target{Type: platforms.TargetRepo, Value: attackRepo}
	case attackOrg != "":
		target = platforms.Target{Type: platforms.TargetOrg, Value: attackOrg}
	default:
		return fmt.Errorf("must specify --repo or --org")
	}

	sessionID := attackSessionID
	if sessionID == "" {
		sessionID = uuid.New().String()[:8]
	}

	ctx, cancel := context.WithTimeout(context.Background(), attackTimeout)
	defer cancel()

	platform, err := registry.GetPlatform("azuredevops")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	orgName := attackOrg
	if orgName == "" {
		return fmt.Errorf("--org is required for Azure DevOps attacks")
	}

	initConfig := platforms.Config{
		Token:       t,
		Concurrency: 10,
		AzureDevOps: &platforms.AzureDevOpsAuth{
			PAT:          t,
			BearerToken:  bt,
			Organization: orgName,
		},
	}
	if strings.HasPrefix(orgName, "https://") || strings.HasPrefix(orgName, "http://") {
		initConfig.BaseURL = orgName
	} else {
		initConfig.BaseURL = fmt.Sprintf("https://dev.azure.com/%s", orgName)
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)

	if err := platform.Init(ctx, initConfig); err != nil {
		return fmt.Errorf("initializing platform: %w", err)
	}

	if target.Type == platforms.TargetRepo {
		if err := verifyWriteAccess(ctx, platform, target); err != nil {
			return err
		}
	}

	verbose := cmdutil.GetVerbose(cmd)
	if verbose {
		fmt.Fprintf(os.Stderr, "Phase 1: Scanning for vulnerabilities...\n")
	}

	scanResult, err := platform.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	allPlugins := registry.GetDetections("azuredevops")
	executor := scanner.NewDetectionExecutor(allPlugins, 10)
	execResult, err := executor.Execute(ctx, scanResult.Workflows)
	if err != nil {
		return fmt.Errorf("detecting vulnerabilities: %w", err)
	}

	if len(execResult.Findings) == 0 && !attackForce && len(attackPlugins) == 0 {
		fmt.Println("No vulnerabilities detected. No attacks applicable.")
		return nil
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Found %d vulnerabilities\n", len(execResult.Findings))
	}

	session := attacks.NewSession(sessionID, target, "azuredevops", orgName)

	extraOpts := make(map[string]string)
	if attackGroup != "" {
		extraOpts["group"] = attackGroup
	}
	if attackConnection != "" {
		extraOpts["connection"] = attackConnection
	}
	if attackConnectionType != "" {
		extraOpts["type"] = attackConnectionType
	}
	if attackSecureFile != "" {
		extraOpts["file"] = attackSecureFile
	}
	if attackUserDescriptor != "" {
		extraOpts["user_descriptor"] = attackUserDescriptor
	}
	if attackOutputFile != "" {
		extraOpts["output_file"] = attackOutputFile
	}
	if attackPool != "" {
		extraOpts["pool"] = attackPool
	}
	if attackCommand != "" {
		extraOpts["command"] = attackCommand
	}
	if attackMethod != "" {
		extraOpts["method"] = attackMethod
	}

	// Read SSH public key from file if specified
	var payload string
	if attackPublicKey != "" {
		keyData, err := os.ReadFile(attackPublicKey)
		if err != nil {
			return fmt.Errorf("reading public key file: %w", err)
		}
		payload = string(keyData)
	}

	if target.Type == platforms.TargetOrg && attackRepo == "" {
		return runOrgWideAttack(ctx, cmd, platform, scanResult, execResult, extraOpts, sessionID, orgName, payload)
	}

	opts := attacks.AttackOptions{
		Target:    target,
		Platform:  platform,
		Findings:  execResult.Findings,
		DryRun:    attackDryRun,
		Verbose:   verbose,
		Timeout:   attackTimeout,
		SessionID: sessionID,
		ExtraOpts: extraOpts,
		Payload:   payload,
	}

	attacksToRun := cmdutil.SelectAttackPlugins("azuredevops", execResult.Findings, cmdutil.AttackSelectionCriteria{
		PluginNames: attackPlugins,
		Category:    attackCategory,
		Force:       attackForce,
	})
	if len(attacksToRun) == 0 {
		fmt.Println("No applicable attacks found for detected vulnerabilities.")
		return nil
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Phase 2: Executing %d attacks (session: %s)...\n", len(attacksToRun), sessionID)
	}

	var results []*attacks.AttackResult
	for _, plugin := range attacksToRun {
		if verbose {
			fmt.Fprintf(os.Stderr, "Executing: %s\n", plugin.Name())
		}

		result, err := plugin.Execute(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Attack %s failed: %v\n", plugin.Name(), err)
			continue
		}

		results = append(results, result)
		session.AddResult(result)
	}

	if err := session.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
	}

	if err := cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), results, sessionID, "trajan ado attack cleanup"); err != nil {
		return err
	}

	if attackOutputFile != "" {
		if err := cmdutil.WriteExtractedDataToFile(attackOutputFile, results); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Printf("Extracted data written to: %s\n", attackOutputFile)
	}

	return nil
}

// runOrgWideAttack iterates over all repositories discovered in the org scan
// and runs the selected attack plugins against each repo.
func runOrgWideAttack(
	ctx context.Context,
	cmd *cobra.Command,
	platform platforms.Platform,
	scanResult *platforms.ScanResult,
	execResult *scanner.ExecutionResult,
	extraOpts map[string]string,
	sessionID string,
	orgName string,
	payload string,
) error {
	if len(scanResult.Repositories) == 0 {
		fmt.Println("No repositories found in organization.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d repositories in organization\n", len(scanResult.Repositories))

	verbose := cmdutil.GetVerbose(cmd)
	var allResults []*attacks.AttackResult
	session := attacks.NewSession(sessionID, platforms.Target{Type: platforms.TargetOrg, Value: orgName}, "azuredevops", orgName)

	for _, repo := range scanResult.Repositories {
		repoSlug := repo.FullName()
		repoTarget := platforms.Target{Type: platforms.TargetRepo, Value: repoSlug}

		var repoFindings []detections.Finding
		for _, f := range execResult.Findings {
			if f.Repository == repoSlug {
				repoFindings = append(repoFindings, f)
			}
		}

		if len(repoFindings) == 0 && !attackForce && len(attackPlugins) == 0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "Skipping %s (no findings)\n", repoSlug)
			}
			continue
		}

		attacksToRun := cmdutil.SelectAttackPlugins("azuredevops", repoFindings, cmdutil.AttackSelectionCriteria{
			PluginNames: attackPlugins,
			Category:    attackCategory,
			Force:       attackForce,
		})
		if len(attacksToRun) == 0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "Skipping %s (no applicable attacks)\n", repoSlug)
			}
			continue
		}

		fmt.Fprintf(os.Stderr, "Attacking %s (%d plugins)...\n", repoSlug, len(attacksToRun))

		opts := attacks.AttackOptions{
			Target:    repoTarget,
			Platform:  platform,
			Findings:  repoFindings,
			DryRun:    attackDryRun,
			Verbose:   verbose,
			Timeout:   attackTimeout,
			SessionID: sessionID,
			ExtraOpts: extraOpts,
			Payload:   payload,
		}

		for _, plugin := range attacksToRun {
			if verbose {
				fmt.Fprintf(os.Stderr, "  Executing: %s against %s\n", plugin.Name(), repoSlug)
			}

			result, err := plugin.Execute(ctx, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Attack %s failed on %s: %v\n", plugin.Name(), repoSlug, err)
				continue
			}

			allResults = append(allResults, result)
			session.AddResult(result)
		}
	}

	if err := session.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save session: %v\n", err)
	}

	if err := cmdutil.OutputAttackResults(cmdutil.GetOutput(cmd), allResults, sessionID, "trajan ado attack cleanup"); err != nil {
		return err
	}

	if attackOutputFile != "" {
		if err := cmdutil.WriteExtractedDataToFile(attackOutputFile, allResults); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Printf("Extracted data written to: %s\n", attackOutputFile)
	}

	return nil
}

func runAttackCleanup(cmd *cobra.Command, args []string) error {
	list, err := cmd.Flags().GetBool("list")
	if err != nil {
		return fmt.Errorf("getting list flag: %w", err)
	}

	if list {
		sessions, err := attacks.ListSessions()
		if err != nil {
			return fmt.Errorf("listing sessions: %w", err)
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
		return fmt.Errorf("must specify --session or --list")
	}

	session, err := attacks.LoadSession(attackSessionID)
	if err != nil {
		return fmt.Errorf("loading session: %w", err)
	}

	orgName := attackOrg
	if session.Org != "" && !cmd.Flags().Changed("org") {
		orgName = session.Org
	}

	ctx := context.Background()

	t := getToken(cmd)
	bt := getBearerToken(cmd)
	if t == "" && bt == "" {
		return fmt.Errorf("no token provided (use --token, --azure-bearer-token, or set AZURE_DEVOPS_PAT/AZURE_BEARER_TOKEN)")
	}

	platform, err := registry.GetPlatform("azuredevops")
	if err != nil {
		return fmt.Errorf("getting platform: %w", err)
	}

	if orgName == "" {
		return fmt.Errorf("--org is required for Azure DevOps cleanup")
	}

	initConfig := platforms.Config{
		Token:       t,
		Concurrency: 10,
		AzureDevOps: &platforms.AzureDevOpsAuth{
			PAT:          t,
			BearerToken:  bt,
			Organization: orgName,
		},
	}
	if strings.HasPrefix(orgName, "https://") || strings.HasPrefix(orgName, "http://") {
		initConfig.BaseURL = orgName
	} else {
		initConfig.BaseURL = fmt.Sprintf("https://dev.azure.com/%s", orgName)
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)

	if err := platform.Init(ctx, initConfig); err != nil {
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

// verifyWriteAccess checks if the token has access to the target repository.
func verifyWriteAccess(ctx context.Context, platform platforms.Platform, target platforms.Target) error {
	p, ok := platform.(*azuredevops.Platform)
	if !ok {
		return fmt.Errorf("unsupported platform for attack verification")
	}

	client := p.Client()
	parts := strings.SplitN(target.Value, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format (expected project/repo)")
	}

	_, err := client.GetRepository(ctx, parts[0], parts[1])
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "404") || strings.Contains(errStr, "does not exist") {
			return fmt.Errorf("repository not found: %s (check that the project and repo names are correct)", target.Value)
		}
		return fmt.Errorf("cannot access repository %s: %w", target.Value, err)
	}

	return nil
}
