package jenkins

import (
	"testing"

	"github.com/praetorian-inc/trajan/internal/registry"
)

func TestInit(t *testing.T) {
	p, err := registry.GetPlatform("jenkins")
	if err != nil {
		t.Fatalf("GetPlatform(jenkins) error = %v", err)
	}
	if p.Name() != "jenkins" {
		t.Errorf("Name() = %q, want %q", p.Name(), "jenkins")
	}
}
