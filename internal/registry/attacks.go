package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/praetorian-inc/trajan/pkg/attacks"
)

var (
	attackMu       sync.RWMutex
	attackRegistry = make(map[string][]attacks.AttackPluginFactory) // platform -> factories
	attackIDs      = make(map[string]bool)                          // platform/name -> registered
	attackByName   = make(map[string]attacks.AttackPluginFactory)   // platform/name -> factory (namespaced to avoid cross-platform collisions)
)

// PluginKey builds a namespaced registry key from platform and plugin name.
func PluginKey(platform, name string) string {
	return platform + "/" + name
}

// RegisterAttackPlugin registers an attack plugin factory for a platform
func RegisterAttackPlugin(platform, name string, factory attacks.AttackPluginFactory) {
	attackMu.Lock()
	defer attackMu.Unlock()

	id := PluginKey(platform, name)
	if attackIDs[id] {
		panic(fmt.Sprintf("attack: Register called twice for %s", id))
	}
	attackIDs[id] = true

	attackRegistry[platform] = append(attackRegistry[platform], factory)
	attackByName[id] = factory
}

// GetAttackPlugins returns new instances of all attack plugins for a platform
func GetAttackPlugins(platform string) []attacks.AttackPlugin {
	attackMu.RLock()
	defer attackMu.RUnlock()
	factories := attackRegistry[platform]
	result := make([]attacks.AttackPlugin, 0, len(factories))
	for _, factory := range factories {
		result = append(result, factory())
	}
	return result
}

// GetAttackPluginByName returns a specific attack plugin by namespaced key (platform/name).
// Example: "github/secrets-dump", "gitlab/ai-probe"
func GetAttackPluginByName(name string) (attacks.AttackPlugin, error) {
	attackMu.RLock()
	defer attackMu.RUnlock()
	factory, ok := attackByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown attack plugin: %s", name)
	}
	return factory(), nil
}

// GetAttackPluginsByCategory returns plugins matching a category
func GetAttackPluginsByCategory(platform string, category attacks.AttackCategory) []attacks.AttackPlugin {
	attackMu.RLock()
	defer attackMu.RUnlock()
	var result []attacks.AttackPlugin
	for _, factory := range attackRegistry[platform] {
		plugin := factory()
		if plugin.Category() == category {
			result = append(result, plugin)
		}
	}
	return result
}

// ListAttackPlugins returns all registered attack plugin names (platform/name format)
func ListAttackPlugins() []string {
	attackMu.RLock()
	defer attackMu.RUnlock()
	names := make([]string, 0, len(attackByName))
	for name := range attackByName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResetAttacks clears the attack registry (for testing)
func ResetAttacks() {
	attackMu.Lock()
	defer attackMu.Unlock()
	attackRegistry = make(map[string][]attacks.AttackPluginFactory)
	attackIDs = make(map[string]bool)
	attackByName = make(map[string]attacks.AttackPluginFactory)
}
