package base

import "github.com/praetorian-inc/trajan/pkg/attacks"

// BaseAttackPlugin provides common functionality for all attack plugins
type BaseAttackPlugin struct {
	name        string
	description string
	platform    string
	category    attacks.AttackCategory
}

// NewBaseAttackPlugin creates a new base attack plugin
func NewBaseAttackPlugin(name, description, platform string, category attacks.AttackCategory) BaseAttackPlugin {
	return BaseAttackPlugin{
		name:        name,
		description: description,
		platform:    platform,
		category:    category,
	}
}

func (p BaseAttackPlugin) Name() string                     { return p.name }
func (p BaseAttackPlugin) Description() string              { return p.description }
func (p BaseAttackPlugin) Platform() string                 { return p.platform }
func (p BaseAttackPlugin) Category() attacks.AttackCategory { return p.category }
