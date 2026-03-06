package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/output"
)

func newSearchCredsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "creds",
		Short: "Search for potential credentials in code",
		Long: `Trajan - Azure DevOps - Enumerate

Search for potential credentials and secrets in code using predefined patterns.
Searches organization-wide using patterns from pkg/platforms/azuredevops/cred_patterns.go.`,
		RunE: runSearchCreds,
	}
}

func runSearchCreds(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runSearchCredsAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runSearchCredsAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	type credResult struct {
		Pattern string
		Count   int
		Results []struct {
			Project    string
			Repository string
			File       string
			Path       string
		}
	}

	var allResults []credResult

	for _, pattern := range azuredevops.CredentialPatterns {
		req := azuredevops.CodeSearchRequest{
			SearchText:    pattern,
			Top:           10, // Limit per pattern
			IncludeFacets: false,
		}

		result, err := client.SearchCodeOrg(ctx, req)
		if err != nil {
			// Continue on error - may not have access to search
			continue
		}

		if result.Count > 0 {
			cr := credResult{
				Pattern: pattern,
				Count:   result.Count,
			}
			for _, r := range result.Results {
				cr.Results = append(cr.Results, struct {
					Project    string
					Repository string
					File       string
					Path       string
				}{
					Project:    r.Project.Name,
					Repository: r.Repository.Name,
					File:       r.FileName,
					Path:       r.Path,
				})
			}
			allResults = append(allResults, cr)
		}
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(allResults)

	case "csv":
		headers := []string{"Pattern", "Project", "Repository", "File", "Path"}
		var rows [][]string
		for _, cr := range allResults {
			for _, r := range cr.Results {
				rows = append(rows, []string{cr.Pattern, r.Project, r.Repository, r.File, r.Path})
			}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(allResults) == 0 {
			fmt.Println("No potential credentials found")
			return nil
		}

		for _, cr := range allResults {
			fmt.Printf("\nPattern: %s (found %d matches)\n", cr.Pattern, cr.Count)
			if len(cr.Results) > 0 {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  PROJECT\tREPOSITORY\tFILE")
				for _, r := range cr.Results {
					fmt.Fprintf(w, "  %s\t%s\t%s\n", r.Project, r.Repository, r.File)
				}
				w.Flush()
			}
		}

		totalMatches := 0
		for _, cr := range allResults {
			totalMatches += cr.Count
		}
		fmt.Printf("\nTotal: %d patterns matched, %d files found\n", len(allResults), totalMatches)
		return nil
	}
}
