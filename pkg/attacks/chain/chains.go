package chain

import "github.com/praetorian-inc/trajan/pkg/attacks"

// ChainDefinition describes a named attack chain
type ChainDefinition struct {
	Name        string
	Description string
	Plugins     []string
	Category    attacks.AttackCategory
}

// PredefinedChains contains all named chain presets
var PredefinedChains = map[string]ChainDefinition{
	"ror": {
		Name:        "ror",
		Description: "Runner-on-Runner: Setup C2, deploy implant, connect shell",
		Plugins:     []string{"c2-setup", "runner-on-runner", "interactive-shell"},
		Category:    attacks.CategoryRunners,
	},
	"secrets": {
		Name:        "secrets",
		Description: "Secrets Exfiltration: Dump pipeline secrets (no C2 needed)",
		Plugins:     []string{"secrets-dump"},
		Category:    attacks.CategorySecrets,
	},
	"persistence": {
		Name:        "persistence",
		Description: "Establish Persistence: Setup C2, deploy persistent backdoor",
		Plugins:     []string{"c2-setup", "persistence"},
		Category:    attacks.CategoryPersistence,
	},
	"full": {
		Name:        "full",
		Description: "Full Attack: C2, RoR, shell, secrets dump, persistence",
		Plugins: []string{
			"c2-setup",
			"runner-on-runner",
			"interactive-shell",
			"secrets-dump",
			"persistence",
		},
		Category: attacks.CategoryCICD,
	},
	"ai-takeover": {
		Name:        "ai-takeover",
		Description: "AI-powered CI/CD takeover chain",
		Plugins:     []string{"runner-on-runner", "secrets-dump", "persistence"},
		Category:    attacks.CategoryCICD,
	},
	"supply-chain": {
		Name:        "supply-chain",
		Description: "Supply chain poisoning via workflow injection and persistence",
		Plugins:     []string{"workflow-injection", "secrets-dump", "persistence"},
		Category:    attacks.CategoryCICD,
	},
	"toctou-exploit": {
		Name:        "toctou-exploit",
		Description: "TOCTOU race condition exploitation",
		Plugins:     []string{"pr-attack", "secrets-dump", "runner-on-runner"},
		Category:    attacks.CategoryCICD,
	},
	"stealth": {
		Name:        "stealth",
		Description: "Stealthy persistence via workflow injection",
		Plugins:     []string{"workflow-injection", "persistence"},
		Category:    attacks.CategoryPersistence,
	},
}

// GetChain returns a chain definition by name
func GetChain(name string) (ChainDefinition, bool) {
	chain, ok := PredefinedChains[name]
	return chain, ok
}

// ListChains returns all available chain names sorted alphabetically
func ListChains() []string {
	// Predefined order for better UX
	return []string{"ai-takeover", "full", "persistence", "ror", "secrets", "stealth", "supply-chain", "toctou-exploit"}
}
