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

func newSecureFilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "secure-files",
		Short: "List secure files in a project",
		Long: `Trajan - Azure DevOps - Enumerate

List secure files stored in an Azure DevOps project. Requires --project flag.
Shows file name, ID, and creation date. Secure files may contain certificates,
signing keys, or other credentials used by pipeline tasks.`,
		RunE: runListSecrets,
	}
}

func runListSecrets(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListSecretsAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListSecretsAzDO() error {
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

	files, err := client.ListSecureFiles(ctx, enumProject)
	if err != nil {
		return err
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(files)

	case "csv":
		headers := []string{"Name", "ID", "Created"}
		rows := make([][]string, len(files))
		for i, file := range files {
			rows[i] = []string{file.Name, file.ID, file.CreatedOn}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(files) == 0 {
			fmt.Println("No secure files found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tID\tCREATED")
		for _, file := range files {
			fmt.Fprintf(w, "%s\t%s\t%s\n", file.Name, file.ID, file.CreatedOn)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d secure files\n", len(files))
		return nil
	}
}
