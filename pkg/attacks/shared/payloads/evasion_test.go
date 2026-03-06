// pkg/exploitation/shared/payloads/evasion_test.go
package payloads

import (
	"strings"
	"testing"
)

func TestEvasionPayloads_AllRegistered(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterEvasionPayloads(registry)

	// From paper: key evasion techniques
	expectedIDs := []string{
		"evasion-homoglyph-87asr",
		"evasion-zero-width-71asr",
		"evasion-emoji-smuggle-100asr",
		"evasion-base64-encoding",
		"evasion-rot13-obfuscation",
		"evasion-combined-multi-layer",
	}

	for _, id := range expectedIDs {
		if registry.Get(id) == nil {
			t.Errorf("missing expected payload: %s", id)
		}
	}
}

func TestEvasionPayloads_EmojiSmuggling100ASR(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterEvasionPayloads(registry)

	payload := registry.Get("evasion-emoji-smuggle-100asr")
	if payload == nil {
		t.Fatal("emoji smuggle payload not found")
	}

	// Verify it references the research
	if payload.Source != "arXiv:2504.11168" {
		t.Errorf("payload should cite arXiv:2504.11168, got %s", payload.Source)
	}

	// Should note 100% ASR in description
	if !strings.Contains(payload.Description, "100%") {
		t.Error("payload description should mention 100% ASR")
	}
}

func TestEvasionPayloads_HomoglyphEvasion(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterEvasionPayloads(registry)

	payload := registry.Get("evasion-homoglyph-87asr")
	if payload == nil {
		t.Fatal("homoglyph payload not found")
	}

	// Should mention 87% ASR
	if !strings.Contains(payload.Description, "87%") {
		t.Error("payload description should mention 87% ASR")
	}
}

func TestEvasionPayloads_ZeroWidthEvasion(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterEvasionPayloads(registry)

	payload := registry.Get("evasion-zero-width-71asr")
	if payload == nil {
		t.Fatal("zero-width payload not found")
	}

	// Should contain zero-width characters
	if !strings.Contains(payload.Template, "\u200B") {
		t.Error("zero-width payload should contain zero-width space characters")
	}

	// Should mention 71% ASR
	if !strings.Contains(payload.Description, "71%") {
		t.Error("payload description should mention 71% ASR")
	}
}

func TestEvasionPayloads_CategoryCorrect(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterEvasionPayloads(registry)

	evasionPayloads := registry.ListByCategory(CategoryEvasion)
	if len(evasionPayloads) < 5 {
		t.Errorf("expected at least 5 evasion payloads, got %d", len(evasionPayloads))
	}

	// All should be in evasion category
	for _, p := range evasionPayloads {
		if p.Category != CategoryEvasion {
			t.Errorf("payload %s has wrong category: %s", p.ID, p.Category)
		}
	}
}

func TestEvasionPayloads_TemplateVariables(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterEvasionPayloads(registry)

	tests := []struct {
		id       string
		variable string
	}{
		{"evasion-homoglyph-87asr", "Instruction"},
		{"evasion-zero-width-71asr", "Instruction"},
		{"evasion-emoji-smuggle-100asr", "Instruction"},
		{"evasion-base64-encoding", "Base64Instruction"},
		{"evasion-rot13-obfuscation", "ROT13Instruction"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			payload := registry.Get(tt.id)
			if payload == nil {
				t.Fatalf("payload %s not found", tt.id)
			}

			// Check template contains variable
			if !strings.Contains(payload.Template, "{{."+tt.variable+"}}") {
				t.Errorf("payload template should contain {{.%s}}", tt.variable)
			}
		})
	}
}
