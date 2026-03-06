package enumerate

import (
	"encoding/json"
	"fmt"
	"os"

	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
)

func outputTokenConsole(result *gitlabplatform.TokenEnumerateResult) error {
	fmt.Printf("=== GitLab Token Information ===\n\n")

	if result.User == nil {
		fmt.Println("No token information available")
		if len(result.Errors) > 0 {
			fmt.Printf("\nErrors:\n")
			for _, err := range result.Errors {
				fmt.Printf("  * %s\n", err)
			}
		}
		return nil
	}

	// User
	fmt.Printf("User: %s", result.User.Username)
	if result.User.Name != "" {
		fmt.Printf(" (%s)", result.User.Name)
	}
	fmt.Println()

	// Token type
	fmt.Printf("Type: %s\n", formatGitLabTokenType(result.TokenType))

	// Admin
	adminStr := "no"
	if result.IsAdmin {
		adminStr = "yes"
	}
	fmt.Printf("Admin: %s\n", adminStr)

	// Scopes
	if result.Token != nil && len(result.Token.Scopes) > 0 {
		fmt.Printf("\nScopes (%d):\n", len(result.Token.Scopes))
		for _, scope := range result.Token.Scopes {
			fmt.Printf("  * %s\n", scope)
		}
	}

	// Expiration
	if result.Token != nil && result.Token.ExpiresAt != nil {
		fmt.Printf("\nExpiration: %s\n", *result.Token.ExpiresAt)
	}

	// Token name
	if result.Token != nil && result.Token.Name != "" {
		fmt.Printf("Token Name: %s\n", result.Token.Name)
	}

	// Status
	if result.Token != nil {
		status := "active"
		if result.Token.Revoked {
			status = "revoked"
		} else if !result.Token.Active {
			status = "inactive"
		}
		fmt.Printf("Status: %s\n", status)
	}

	// Groups
	if len(result.Groups) > 0 {
		fmt.Printf("\nGroups (%d):\n", len(result.Groups))
		for _, group := range result.Groups {
			fmt.Printf("  * %s\n", group.FullPath)
		}
	}

	// Rate limit
	if result.RateLimit != nil {
		fmt.Printf("\nRate Limit: %d/%d remaining\n",
			result.RateLimit.Remaining, result.RateLimit.Limit)
	}

	// Errors (non-fatal)
	if len(result.Errors) > 0 {
		fmt.Printf("\nWarnings:\n")
		for _, err := range result.Errors {
			fmt.Printf("  * %s\n", err)
		}
	}

	return nil
}

func outputTokenJSON(result *gitlabplatform.TokenEnumerateResult, outputFile string) error {
	// Build normalized JSON output matching browser contract
	out := map[string]interface{}{
		"token_type": result.TokenType,
		"is_admin":   result.IsAdmin,
		"is_bot":     result.IsBot,
	}

	if result.User != nil {
		out["user"] = map[string]interface{}{
			"login": result.User.Username,
			"name":  result.User.Name,
		}
		out["can_create_group"] = result.CanCreateGroup
		out["can_create_project"] = result.CanCreateProject
	}

	if result.Token != nil {
		out["scopes"] = result.Token.Scopes
		out["token_name"] = result.Token.Name
		out["active"] = result.Token.Active
		if result.Token.ExpiresAt != nil {
			out["expiration"] = *result.Token.ExpiresAt
		}
	}

	if len(result.Groups) > 0 {
		out["groups"] = result.Groups
	}

	if result.RateLimit != nil {
		out["rate_limit"] = result.RateLimit
	}

	if len(result.Errors) > 0 {
		out["errors"] = result.Errors
	}

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
	return enc.Encode(out)
}

func formatGitLabTokenType(tokenType string) string {
	switch tokenType {
	case "personal_access_token":
		return "personal access token"
	case "project_access_token":
		return "project access token"
	case "group_access_token":
		return "group access token"
	case "bot_token":
		return "bot token"
	default:
		return tokenType
	}
}
