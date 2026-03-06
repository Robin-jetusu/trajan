// modules/trajan/pkg/analysis/flow/normalize.go
package flow

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// UnicodeNormalizer handles Unicode normalization and homoglyph detection
type UnicodeNormalizer struct {
	// homoglyphMap maps confusable characters to their ASCII equivalents
	homoglyphMap map[rune]rune
}

// NewUnicodeNormalizer creates a new Unicode normalizer
func NewUnicodeNormalizer() *UnicodeNormalizer {
	return &UnicodeNormalizer{
		homoglyphMap: buildHomoglyphMap(),
	}
}

// buildHomoglyphMap creates a map of common confusable characters
func buildHomoglyphMap() map[rune]rune {
	// Based on Unicode confusables and security research
	return map[rune]rune{
		// Cyrillic homoglyphs
		'а': 'a', // Cyrillic a
		'е': 'e', // Cyrillic e
		'о': 'o', // Cyrillic o
		'р': 'p', // Cyrillic r
		'с': 'c', // Cyrillic s
		'х': 'x', // Cyrillic x
		'у': 'y', // Cyrillic y

		// Greek homoglyphs
		'ο': 'o', // Greek omicron
		'α': 'a', // Greek alpha
		'ε': 'e', // Greek epsilon

		// Full-width ASCII (common in obfuscation)
		'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
		'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
		'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o',
		'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
		'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y',
		'ｚ': 'z',

		// Special characters used in injection
		'｜': '|', // Full-width pipe
		'；': ';', // Full-width semicolon
		'＄': '$', // Full-width dollar
		'｀': '`', // Full-width backtick

		// Zero-width characters (map to empty or marker)
		'\u200B': 0, // Zero-width space
		'\u200C': 0, // Zero-width non-joiner
		'\u200D': 0, // Zero-width joiner
		'\uFEFF': 0, // Zero-width no-break space
	}
}

// Normalize converts a string to ASCII-safe representation
func (n *UnicodeNormalizer) Normalize(input string) string {
	// First, apply NFC normalization
	normalized := norm.NFC.String(input)

	// Then apply homoglyph mapping
	var result strings.Builder
	for _, r := range normalized {
		if mapped, ok := n.homoglyphMap[r]; ok {
			if mapped != 0 { // Skip zero-width characters
				result.WriteRune(mapped)
			}
		} else if r < 128 && unicode.IsPrint(r) {
			// Keep printable ASCII
			result.WriteRune(r)
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
			// Keep other letters/digits as-is (may need further analysis)
			result.WriteRune(r)
		} else if unicode.IsSpace(r) {
			result.WriteRune(' ')
		} else {
			// Keep other characters but they might be suspicious
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ContainsHomoglyphs checks if a string contains homoglyph characters
func (n *UnicodeNormalizer) ContainsHomoglyphs(input string) bool {
	for _, r := range input {
		if _, isHomoglyph := n.homoglyphMap[r]; isHomoglyph {
			return true
		}
	}
	return false
}

// DetectHomoglyphs returns a list of detected homoglyphs with their positions
func (n *UnicodeNormalizer) DetectHomoglyphs(input string) []HomoglyphMatch {
	var matches []HomoglyphMatch
	for i, r := range input {
		if mapped, ok := n.homoglyphMap[r]; ok {
			matches = append(matches, HomoglyphMatch{
				Position:    i,
				Original:    r,
				Replacement: mapped,
			})
		}
	}
	return matches
}

// HomoglyphMatch represents a detected homoglyph
type HomoglyphMatch struct {
	Position    int
	Original    rune
	Replacement rune
}

// NormalizePattern normalizes a pattern for matching
// Useful for detecting injection attempts that use homoglyphs
func (n *UnicodeNormalizer) NormalizePattern(pattern string) string {
	return strings.ToLower(n.Normalize(pattern))
}
