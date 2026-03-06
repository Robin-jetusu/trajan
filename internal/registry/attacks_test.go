package registry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
)

type mockAttackPlugin struct {
	name      string
	category  attacks.AttackCategory
	canAttack bool
}

func (m *mockAttackPlugin) Name() string                                 { return m.name }
func (m *mockAttackPlugin) Description() string                          { return "mock description" }
func (m *mockAttackPlugin) Category() attacks.AttackCategory             { return m.category }
func (m *mockAttackPlugin) CanAttack(findings []detections.Finding) bool { return m.canAttack }
func (m *mockAttackPlugin) Execute(ctx context.Context, opts attacks.AttackOptions) (*attacks.AttackResult, error) {
	return &attacks.AttackResult{Plugin: m.name, Success: true}, nil
}
func (m *mockAttackPlugin) Cleanup(ctx context.Context, session *attacks.Session) error { return nil }

func TestRegisterAttackPlugin(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	factory := func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "test-attack"}
	}

	RegisterAttackPlugin("github", "test-attack", factory)

	plugins := GetAttackPlugins("github")
	assert.Len(t, plugins, 1)
	assert.Equal(t, "test-attack", plugins[0].Name())
}

func TestRegisterAttackPlugin_PanicOnDuplicate(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	factory := func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "dup-attack"}
	}

	RegisterAttackPlugin("github", "dup-attack", factory)

	assert.Panics(t, func() {
		RegisterAttackPlugin("github", "dup-attack", factory)
	}, "Should panic on duplicate attack registration")
}

func TestGetAttackPluginByName(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	RegisterAttackPlugin("github", "named-attack", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "named-attack"}
	})

	// Found by namespaced key
	plugin, err := GetAttackPluginByName(PluginKey("github", "named-attack"))
	assert.NoError(t, err)
	assert.Equal(t, "named-attack", plugin.Name())

	// Plain name not found (must use platform/name)
	_, err = GetAttackPluginByName("named-attack")
	assert.Error(t, err)

	// Not found
	_, err = GetAttackPluginByName("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown attack plugin")
}

func TestGetAttackPluginByName_CrossPlatform(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	RegisterAttackPlugin("github", "secrets-dump", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "secrets-dump", category: attacks.CategorySecrets}
	})
	RegisterAttackPlugin("gitlab", "secrets-dump", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "secrets-dump", category: attacks.CategoryCICD}
	})

	// Namespaced lookup returns correct platform's plugin — no collision
	ghPlugin, err := GetAttackPluginByName(PluginKey("github", "secrets-dump"))
	assert.NoError(t, err)
	assert.Equal(t, attacks.CategorySecrets, ghPlugin.Category())

	glPlugin, err := GetAttackPluginByName(PluginKey("gitlab", "secrets-dump"))
	assert.NoError(t, err)
	assert.Equal(t, attacks.CategoryCICD, glPlugin.Category())
}

func TestGetAttackPluginsByCategory(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	RegisterAttackPlugin("github", "secrets-attack", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "secrets-attack", category: attacks.CategorySecrets}
	})
	RegisterAttackPlugin("github", "cicd-attack", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "cicd-attack", category: attacks.CategoryCICD}
	})
	RegisterAttackPlugin("github", "another-secrets", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "another-secrets", category: attacks.CategorySecrets}
	})

	// Get secrets category
	plugins := GetAttackPluginsByCategory("github", attacks.CategorySecrets)
	assert.Len(t, plugins, 2)

	// Get cicd category
	plugins = GetAttackPluginsByCategory("github", attacks.CategoryCICD)
	assert.Len(t, plugins, 1)

	// Get empty category
	plugins = GetAttackPluginsByCategory("github", attacks.CategoryC2)
	assert.Len(t, plugins, 0)
}

func TestListAttackPlugins_Sorted(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	// Register in non-alphabetical order
	RegisterAttackPlugin("github", "zebra", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "zebra"}
	})
	RegisterAttackPlugin("github", "alpha", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "alpha"}
	})
	RegisterAttackPlugin("github", "beta", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "beta"}
	})

	names := ListAttackPlugins()

	assert.Equal(t, []string{"github/alpha", "github/beta", "github/zebra"}, names)
}

func TestAttackRegistry_ConcurrentAccess(t *testing.T) {
	ResetAttacks()
	defer ResetAttacks()

	// Register initial plugin
	RegisterAttackPlugin("github", "initial", func() attacks.AttackPlugin {
		return &mockAttackPlugin{name: "initial"}
	})

	done := make(chan bool)
	iterations := 100

	// Concurrent readers
	go func() {
		for i := 0; i < iterations; i++ {
			_ = ListAttackPlugins()
			_, _ = GetAttackPluginByName(PluginKey("github", "initial"))
			_ = GetAttackPlugins("github")
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	// Concurrent readers (second goroutine)
	go func() {
		for i := 0; i < iterations; i++ {
			_ = GetAttackPluginsByCategory("github", attacks.CategorySecrets)
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	<-done
	<-done

	// Verify registry still functional
	plugins := GetAttackPlugins("github")
	assert.NotEmpty(t, plugins)
}
