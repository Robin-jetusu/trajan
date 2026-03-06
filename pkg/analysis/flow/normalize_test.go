// modules/trajan/pkg/analysis/flow/normalize_test.go
package flow

import "testing"

func TestUnicodeNormalization(t *testing.T) {
	normalizer := NewUnicodeNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ASCII unchanged",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "Full-width to ASCII",
			input:    "ｈｅｌｌｏ", // Full-width ASCII
			expected: "hello",
		},
		{
			name:     "Cyrillic homoglyphs",
			input:    "hеllo", // 'е' is Cyrillic
			expected: "hello",
		},
		{
			name:     "Mixed homoglyphs",
			input:    "еxеc", // Cyrillic 'е' looks like 'e'
			expected: "exec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizer.Normalize(tt.input)
			if result != tt.expected {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHomoglyphDetection(t *testing.T) {
	normalizer := NewUnicodeNormalizer()

	tests := []struct {
		name    string
		input   string
		hasHomo bool
	}{
		{
			name:    "Pure ASCII",
			input:   "normal text",
			hasHomo: false,
		},
		{
			name:    "Cyrillic homoglyph",
			input:   "hеllo", // Cyrillic е
			hasHomo: true,
		},
		{
			name:    "Full-width characters",
			input:   "ｓｅｃｒｅｔ",
			hasHomo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizer.ContainsHomoglyphs(tt.input)
			if result != tt.hasHomo {
				t.Errorf("ContainsHomoglyphs(%q) = %v, want %v", tt.input, result, tt.hasHomo)
			}
		})
	}
}
