package chain

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/attacks"
)

// ChainExecutor orchestrates attack chain execution
type ChainExecutor struct {
	session *attacks.Session
	context *ChainContext
	results []*attacks.AttackResult
	verbose bool
}

// NewChainExecutor creates a new chain executor
func NewChainExecutor(session *attacks.Session, verbose bool) *ChainExecutor {
	return &ChainExecutor{
		session: session,
		results: make([]*attacks.AttackResult, 0),
		verbose: verbose,
	}
}

// ExecuteChain runs a named chain or custom plugin sequence
func (e *ChainExecutor) ExecuteChain(
	ctx context.Context,
	opts attacks.AttackOptions,
	chainName string,
	customPlugins []string,
) ([]*attacks.AttackResult, error) {
	// Determine plugin sequence
	var plugins []string
	if chainName != "" {
		chain, ok := GetChain(chainName)
		if !ok {
			return nil, fmt.Errorf("unknown chain: %s", chainName)
		}
		plugins = chain.Plugins
	} else if len(customPlugins) > 0 {
		plugins = customPlugins
	} else {
		return nil, fmt.Errorf("must specify --chain or --chain-plugins")
	}

	e.context = NewChainContext(opts)

	// Validate chain before execution
	if err := e.validateChain(plugins); err != nil {
		return nil, fmt.Errorf("chain validation failed: %w", err)
	}

	// Execute plugins in sequence
	for _, pluginName := range plugins {
		// Skip c2-setup if C2 repo already provided
		if pluginName == "c2-setup" && e.context.C2Repo != "" {
			if e.verbose {
				fmt.Fprintf(os.Stderr, "Skipping %s: C2 repo already provided (%s)\n",
					pluginName, e.context.C2Repo)
			}
			continue
		}

		plugin, err := registry.GetAttackPluginByName(registry.PluginKey(e.session.PlatformName, pluginName))
		if err != nil {
			return e.results, fmt.Errorf("getting plugin %s: %w", pluginName, err)
		}

		if !plugin.CanAttack(opts.Findings) {
			if e.verbose {
				fmt.Fprintf(os.Stderr, "Skipping %s: not applicable to findings\n", pluginName)
			}
			continue
		}

		if e.verbose {
			fmt.Fprintf(os.Stderr, "Executing: %s\n", plugin.Name())
		}

		// Prepare options with chain context
		chainOpts := opts
		chainOpts.SessionID = e.session.ID

		// Propagate context values to ExtraOpts for backward compatibility
		e.populateExtraOpts(&chainOpts)

		result, err := plugin.Execute(ctx, chainOpts)
		if err != nil {
			// Rollback on failure
			rollbackErr := e.rollback(ctx, opts)
			if rollbackErr != nil {
				return e.results, fmt.Errorf("plugin %s failed: %w; rollback also failed: %v",
					pluginName, err, rollbackErr)
			}
			return e.results, fmt.Errorf("plugin %s failed (rolled back): %w", pluginName, err)
		}

		if !result.Success {
			// Logical failure (not error) - still rollback
			rollbackErr := e.rollback(ctx, opts)
			if rollbackErr != nil {
				return e.results, fmt.Errorf("plugin %s failed: %s; rollback also failed: %v",
					pluginName, result.Message, rollbackErr)
			}
			return e.results, fmt.Errorf("plugin %s failed (rolled back): %s",
				pluginName, result.Message)
		}

		e.updateContextFromResult(pluginName, result)
		e.context.MarkExecuted(pluginName)

		// Track cleanup actions
		for _, action := range result.CleanupActions {
			e.context.AddCleanupAction(action)
		}

		// Store result
		e.results = append(e.results, result)
		e.session.AddResult(result)
	}

	return e.results, nil
}

// validateChain ensures all plugins exist and dependencies are satisfied
func (e *ChainExecutor) validateChain(plugins []string) error {
	seen := make(map[string]bool)

	for i, pluginName := range plugins {
		plugin, err := registry.GetAttackPluginByName(registry.PluginKey(e.session.PlatformName, pluginName))
		if err != nil {
			return fmt.Errorf("plugin %q not found", pluginName)
		}

		// Check dependencies (if chainable)
		if chainable, ok := plugin.(attacks.ChainableAttackPlugin); ok {
			for _, dep := range chainable.Dependencies() {
				if !seen[dep] && dep != "" {
					// Check if dependency appears later in chain (error)
					foundLater := false
					for j := i + 1; j < len(plugins); j++ {
						if plugins[j] == dep {
							foundLater = true
							break
						}
					}
					if foundLater {
						return fmt.Errorf("plugin %q requires %q which appears later in chain",
							pluginName, dep)
					}
					// Dependency not in chain - might be optional or error
					// For now, allow it (optional deps or provided via context)
				}
			}
		}

		seen[pluginName] = true
	}

	return nil
}

// populateExtraOpts copies ChainContext values to ExtraOpts for backward compatibility
func (e *ChainExecutor) populateExtraOpts(opts *attacks.AttackOptions) {
	if opts.ExtraOpts == nil {
		opts.ExtraOpts = make(map[string]string)
	}

	if e.context.C2Repo != "" {
		opts.ExtraOpts["c2_repo"] = e.context.C2Repo
	}
	opts.ExtraOpts["target_os"] = e.context.TargetOS
	opts.ExtraOpts["target_arch"] = e.context.TargetArch
	opts.ExtraOpts["runner_labels"] = strings.Join(e.context.Labels, ",")
	if e.context.KeepAlive {
		opts.ExtraOpts["keep_alive"] = "true"
	}
}

// updateContextFromResult extracts state from plugin result
func (e *ChainExecutor) updateContextFromResult(pluginName string, result *attacks.AttackResult) {
	artifacts := ExtractArtifacts(result)

	for key, value := range artifacts {
		e.context.Set(key, value)
	}

	// Track artifacts
	e.context.Artifacts = append(e.context.Artifacts, result.Artifacts...)
}

// rollback executes cleanup actions in reverse order
func (e *ChainExecutor) rollback(ctx context.Context, opts attacks.AttackOptions) error {
	if e.verbose {
		fmt.Fprintf(os.Stderr, "Rolling back attack chain...\n")
	}

	var errors []string

	// Get cleanup actions in reverse order (LIFO)
	actions := e.context.GetCleanupActions()

	for _, action := range actions {
		if e.verbose {
			fmt.Fprintf(os.Stderr, "  Cleaning up %s: %s\n", action.Type, action.Identifier)
		}

		for _, result := range e.results {
			for _, ca := range result.CleanupActions {
				if ca.Identifier == action.Identifier {
					plugin, err := registry.GetAttackPluginByName(registry.PluginKey(e.session.PlatformName, result.Plugin))
					if err != nil {
						errors = append(errors, fmt.Sprintf("get plugin %s: %v", result.Plugin, err))
						continue
					}

					if err := plugin.Cleanup(ctx, e.session); err != nil {
						errors = append(errors, fmt.Sprintf("cleanup %s: %v", result.Plugin, err))
					}
					break
				}
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("rollback errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// ChainResult represents the outcome of a chain execution
type ChainResult struct {
	Chain     string
	SessionID string
	StartTime time.Time
	EndTime   time.Time
	Success   bool
	FailedAt  string // Plugin name where failure occurred
	Error     error
	Results   []*attacks.AttackResult
}
