// pkg/github/init.go
package github

import (
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterPlatform("github", func() platforms.Platform {
		return NewPlatform()
	})
}
