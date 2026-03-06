package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/output"
)

func newVariableGroupsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "variable-groups",
		Short: "List variable groups in a project",
		Long: `Trajan - Azure DevOps - Enumerate

List variable groups defined in an Azure DevOps project. Requires --project flag.
Shows group ID, name, type, and variable count. Variable groups may contain
secrets and credentials accessible to pipelines at runtime.`,
		RunE: runListVariables,
	}
}

func runListVariables(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListVariablesAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListVariablesAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	if enumProject == "" {
		return fmt.Errorf("--project is required for this command")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	varGroups, err := client.ListVariableGroups(ctx, enumProject)
	if err != nil {
		return err
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(varGroups)

	case "csv":
		headers := []string{"ID", "Name", "Type", "Description", "Variables"}
		rows := make([][]string, len(varGroups))
		for i, vg := range varGroups {
			desc := vg.Description
			if desc == "" {
				desc = "-"
			}
			rows[i] = []string{fmt.Sprintf("%d", vg.ID), vg.Name, vg.Type, desc, fmt.Sprintf("%d", len(vg.Variables))}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(varGroups) == 0 {
			fmt.Println("No variable groups found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tVARIABLES")
		for _, vg := range varGroups {
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\n", vg.ID, vg.Name, vg.Type, len(vg.Variables))
		}
		w.Flush()

		fmt.Printf("\nTotal: %d variable groups\n", len(varGroups))
		return nil
	}
}
