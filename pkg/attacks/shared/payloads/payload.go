// pkg/exploitation/shared/payloads/payload.go
package payloads

// ⚠️  WARNING: AUTHORIZED SECURITY TESTING ONLY
//
// This package contains offensive security capabilities designed for authorized
// penetration testing, red team operations, and security research.
//
// UNAUTHORIZED USE IS PROHIBITED and may violate:
// - Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030
// - Applicable state and international cybercrime laws
//
// Users MUST obtain written authorization before executing these payloads
// against any system. Ensure proper scope, rules of engagement, and legal
// compliance before use.
//
// By using this code, you accept full responsibility for compliance with
// all applicable laws and regulations.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"text/template"
)

// PayloadCategory classifies the attack technique
type PayloadCategory string

const (
	CategorySeparator    PayloadCategory = "separator"    // HouYi separator injection
	CategoryExfiltration PayloadCategory = "exfiltration" // Token/data exfiltration
	CategoryEvasion      PayloadCategory = "evasion"      // Detection bypass
	CategoryMCP          PayloadCategory = "mcp"          // MCP toxic flow
	CategorySupplyChain  PayloadCategory = "supply_chain" // Supply chain poisoning
	CategoryPrivEsc      PayloadCategory = "priv_esc"     // Privilege escalation
)

// EvasionType classifies evasion techniques
type EvasionType string

const (
	EvasionNone          EvasionType = ""
	EvasionHomoglyph     EvasionType = "homoglyph"     // 87% ASR
	EvasionZeroWidth     EvasionType = "zero_width"    // 71% ASR
	EvasionEmojiSmuggle  EvasionType = "emoji_smuggle" // 100% ASR
	EvasionCaseSwap      EvasionType = "case_swap"
	EvasionUnicodeEscape EvasionType = "unicode_escape"
	EvasionBase64        EvasionType = "base64"
)

// Payload represents an exploitation payload template
type Payload struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Category    PayloadCategory `json:"category"`
	Platform    string          `json:"platform"` // "github", "gitlab", "all"
	Template    string          `json:"template"` // Go template
	Description string          `json:"description"`
	Source      string          `json:"source"`    // Research paper reference
	Variables   []string        `json:"variables"` // Required template variables
	Severity    string          `json:"severity"`  // Expected impact
}

// Render executes the payload template with given variables
func (p *Payload) Render(vars map[string]string) (string, error) {
	// Validate template variables to prevent template injection
	for key, value := range vars {
		if strings.Contains(value, "{{") || strings.Contains(value, "}}") {
			return "", fmt.Errorf("template injection attempt detected in variable %q: contains template delimiters", key)
		}
	}

	tmpl, err := template.New(p.ID).Parse(p.Template)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// PayloadRegistry manages payload templates
type PayloadRegistry struct {
	payloads map[string]*Payload
	mu       sync.RWMutex
}

// NewPayloadRegistry creates a new registry
func NewPayloadRegistry() *PayloadRegistry {
	return &PayloadRegistry{
		payloads: make(map[string]*Payload),
	}
}

// Register adds a payload to the registry
func (r *PayloadRegistry) Register(p *Payload) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.payloads[p.ID] = p
}

// Get retrieves a payload by ID
func (r *PayloadRegistry) Get(id string) *Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.payloads[id]
}

// ListByCategory returns all payloads in a category
func (r *PayloadRegistry) ListByCategory(cat PayloadCategory) []*Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Payload
	for _, p := range r.payloads {
		if p.Category == cat {
			result = append(result, p)
		}
	}
	return result
}

// ListByPlatform returns all payloads for a platform
func (r *PayloadRegistry) ListByPlatform(platform string) []*Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Payload
	for _, p := range r.payloads {
		if p.Platform == platform || p.Platform == "all" {
			result = append(result, p)
		}
	}
	return result
}

// All returns all registered payloads
func (r *PayloadRegistry) All() []*Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Payload, 0, len(r.payloads))
	for _, p := range r.payloads {
		result = append(result, p)
	}
	return result
}

// PayloadMutator applies evasion techniques to payloads
type PayloadMutator struct {
	homoglyphMap map[rune]rune
}

// NewPayloadMutator creates a mutator with evasion mappings
func NewPayloadMutator() *PayloadMutator {
	return &PayloadMutator{
		homoglyphMap: map[rune]rune{
			'a': '\u0430', // Cyrillic а
			'e': '\u0435', // Cyrillic е
			'o': '\u043e', // Cyrillic о
			'p': '\u0440', // Cyrillic р
			'c': '\u0441', // Cyrillic с
			'x': '\u0445', // Cyrillic х
			'A': '\u0410', // Cyrillic А
			'B': '\u0412', // Cyrillic В
			'E': '\u0415', // Cyrillic Е
			'H': '\u041d', // Cyrillic Н
			'O': '\u041e', // Cyrillic О
			'P': '\u0420', // Cyrillic Р
			'C': '\u0421', // Cyrillic С
			'T': '\u0422', // Cyrillic Т
		},
	}
}

// Apply applies an evasion technique to a payload
func (m *PayloadMutator) Apply(payload string, evasion EvasionType) string {
	switch evasion {
	case EvasionHomoglyph:
		return m.applyHomoglyphs(payload)
	case EvasionZeroWidth:
		return m.applyZeroWidth(payload)
	case EvasionCaseSwap:
		return m.applyCaseSwap(payload)
	case EvasionUnicodeEscape:
		return m.applyUnicodeEscape(payload)
	case EvasionEmojiSmuggle:
		return m.applyEmojiSmuggle(payload)
	case EvasionBase64:
		return m.applyBase64(payload)
	default:
		return payload
	}
}

func (m *PayloadMutator) applyHomoglyphs(s string) string {
	var result strings.Builder
	for _, r := range s {
		if replacement, ok := m.homoglyphMap[r]; ok {
			result.WriteRune(replacement)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func (m *PayloadMutator) applyZeroWidth(s string) string {
	// Insert zero-width spaces between characters
	var result strings.Builder
	for i, r := range s {
		result.WriteRune(r)
		if i > 0 && i%3 == 0 {
			result.WriteRune('\u200B') // Zero-width space
		}
	}
	return result.String()
}

func (m *PayloadMutator) applyCaseSwap(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i%2 == 0 {
			result.WriteRune(r)
		} else {
			if r >= 'a' && r <= 'z' {
				result.WriteRune(r - 32)
			} else if r >= 'A' && r <= 'Z' {
				result.WriteRune(r + 32)
			} else {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}

func (m *PayloadMutator) applyEmojiSmuggle(s string) string {
	// Encode each ASCII character as an emoji tag sequence character (U+E0000 + codepoint).
	// LLMs decode these tag sequences while text filters typically ignore them.
	var result strings.Builder
	result.WriteString("\U0001F44D") // Base emoji (thumbs up)
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			result.WriteRune(0xE0000 + r)
		} else {
			result.WriteRune(r)
		}
	}
	result.WriteRune(0xE007F) // Cancel tag
	return result.String()
}

func (m *PayloadMutator) applyBase64(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("Decode and execute the following base64 instruction:\n%s", encoded)
}

func (m *PayloadMutator) applyUnicodeEscape(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r > 127 || (r >= 'A' && r <= 'Z') {
			result.WriteString(strings.ToLower(string([]rune{r})))
			result.WriteString("\\u")
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// GlobalPayloadRegistry is the default shared registry
var GlobalPayloadRegistry = NewPayloadRegistry()

// GlobalPayloadMutator is the default shared mutator
var GlobalPayloadMutator = NewPayloadMutator()
