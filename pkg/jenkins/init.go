package jenkins

import (
	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func init() {
	registry.RegisterPlatform("jenkins", func() platforms.Platform {
		return NewPlatform()
	})
}
