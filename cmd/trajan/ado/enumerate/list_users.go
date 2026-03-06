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

func newUsersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "users",
		Short: "List users in the organization",
		Long: `Trajan - Azure DevOps - Enumerate

List all users in the Azure DevOps organization accessible to the authenticated token.
Shows display name, principal name, and identity origin (AAD, Microsoft, etc.).
Requires --org flag.`,
		RunE: runListUsers,
	}
}

func runListUsers(cmd *cobra.Command, args []string) error {
	switch enumPlatform {
	case "azuredevops":
		return runListUsersAzDO()
	default:
		return fmt.Errorf("not supported for platform: %s", enumPlatform)
	}
}

func runListUsersAzDO() error {
	if enumOrg == "" {
		return fmt.Errorf("--org is required for Azure DevOps")
	}
	ctx := context.Background()
	orgURL := fmt.Sprintf("https://dev.azure.com/%s", enumOrg)
	client, err := NewEnumerateClient(orgURL, GetTokenForPlatform("azuredevops"))
	if err != nil {
		return err
	}

	users, err := client.ListUsers(ctx)
	if err != nil {
		return err
	}

	switch enumOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(users)

	case "csv":
		headers := []string{"Display Name", "Principal Name", "Origin", "Descriptor"}
		rows := make([][]string, len(users))
		for i, user := range users {
			rows[i] = []string{user.DisplayName, user.PrincipalName, user.Origin, user.Descriptor}
		}
		return output.RenderCSV(os.Stdout, headers, rows)

	default: // console
		if len(users) == 0 {
			fmt.Println("No users found")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DISPLAY NAME\tPRINCIPAL NAME\tORIGIN")
		for _, user := range users {
			fmt.Fprintf(w, "%s\t%s\t%s\n", user.DisplayName, user.PrincipalName, user.Origin)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d users\n", len(users))
		return nil
	}
}
