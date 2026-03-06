package enumerate

import (
	"encoding/json"
	"fmt"
	"os"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

func outputSecretsConsole(result *gitlabplatform.SecretsEnumerateResult) error {
	fmt.Printf("=== Secrets Enumeration ===\n\n")

	total := countVariables(result)
	if total == 0 {
		fmt.Println("No variables found")
		printSecretsErrors(result)
		return nil
	}

	fmt.Printf("Total: %d variables\n", total)

	// Instance variables
	if len(result.InstanceVariables) > 0 {
		fmt.Printf("\nInstance Variables (%d):\n", len(result.InstanceVariables))
		for _, v := range result.InstanceVariables {
			fmt.Printf("  * %s [%s%s, scope: %s]\n", v.Key, v.VariableType, variableFlags(v), v.EnvironmentScope)
		}
	}

	// Group variables
	for group, vars := range result.GroupVariables {
		if len(vars) > 0 {
			fmt.Printf("\nGroup Variables - %s (%d):\n", group, len(vars))
			for _, v := range vars {
				fmt.Printf("  * %s [%s%s, scope: %s]\n", v.Key, v.VariableType, variableFlags(v), v.EnvironmentScope)
			}
		}
	}

	// Project variables
	for project, vars := range result.ProjectVariables {
		if len(vars) > 0 {
			fmt.Printf("\nProject Variables - %s (%d):\n", project, len(vars))
			for _, v := range vars {
				fmt.Printf("  * %s [%s%s, scope: %s]\n", v.Key, v.VariableType, variableFlags(v), v.EnvironmentScope)
			}
		}
	}

	printSecretsErrors(result)

	fmt.Printf("\nNote: Secret values are retrievable via API for Maintainer+ access\n")

	return nil
}

func outputSecretsJSON(result *gitlabplatform.SecretsEnumerateResult, outputFile string) error {
	enc := json.NewEncoder(os.Stdout)
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		enc = json.NewEncoder(f)
	}

	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func countVariables(result *gitlabplatform.SecretsEnumerateResult) int {
	total := len(result.InstanceVariables)
	for _, vars := range result.GroupVariables {
		total += len(vars)
	}
	for _, vars := range result.ProjectVariables {
		total += len(vars)
	}
	return total
}

func variableFlags(v gitlabplatform.Variable) string {
	flags := ""
	if v.Protected {
		flags += ", protected"
	}
	if v.Masked {
		flags += ", masked"
	}
	if v.Hidden {
		flags += ", hidden"
	}
	return flags
}

func printSecretsErrors(result *gitlabplatform.SecretsEnumerateResult) {
	if len(result.PermissionErrors) > 0 {
		fmt.Printf("\nPermission Errors (%d):\n", len(result.PermissionErrors))
		for _, err := range result.PermissionErrors {
			fmt.Printf("  * %s\n", err)
		}
	}
	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("  * %s\n", err)
		}
	}
}
