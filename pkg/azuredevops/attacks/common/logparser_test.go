package common

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDoubleBase64Secrets_Valid(t *testing.T) {
	// Double-encode a secret: value -> base64 -> base64
	secret := "my-secret-value"
	firstEncode := base64.StdEncoding.EncodeToString([]byte(secret))
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(firstEncode))

	result := ParseDoubleBase64Secrets(doubleEncoded)
	assert.Equal(t, []string{secret}, result)
}

func TestParseDoubleBase64Secrets_MultipleLines(t *testing.T) {
	secret1 := "secret-one"
	secret2 := "secret-two"
	enc1 := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret1))))
	enc2 := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret2))))

	input := enc1 + "\n" + enc2
	result := ParseDoubleBase64Secrets(input)
	assert.Equal(t, []string{secret1, secret2}, result)
}

func TestParseDoubleBase64Secrets_WithADOTimestamp(t *testing.T) {
	secret := "timestamped-secret"
	firstEncode := base64.StdEncoding.EncodeToString([]byte(secret))
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(firstEncode))

	// ADO prepends ISO 8601 timestamps to log lines
	input := "2026-02-24T15:18:41.1234567Z " + doubleEncoded
	result := ParseDoubleBase64Secrets(input)
	assert.Equal(t, []string{secret}, result)
}

func TestParseDoubleBase64Secrets_Empty(t *testing.T) {
	result := ParseDoubleBase64Secrets("")
	assert.Empty(t, result)
	assert.NotNil(t, result) // Should be empty slice, not nil
}

func TestParseDoubleBase64Secrets_NonBase64Lines(t *testing.T) {
	input := "this is not base64\nanother non-base64 line\n"
	result := ParseDoubleBase64Secrets(input)
	assert.Empty(t, result)
}

func TestParseDoubleBase64Secrets_MixedContent(t *testing.T) {
	secret := "mixed-secret"
	firstEncode := base64.StdEncoding.EncodeToString([]byte(secret))
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(firstEncode))

	input := "some random log line\n" + doubleEncoded + "\nanother log line\n"
	result := ParseDoubleBase64Secrets(input)
	assert.Equal(t, []string{secret}, result)
}

func TestParseDoubleBase64Secrets_SingleBase64Only(t *testing.T) {
	// Single base64 encoding should not be decoded (needs double)
	secret := "single-encoded"
	singleEncoded := base64.StdEncoding.EncodeToString([]byte(secret))

	result := ParseDoubleBase64Secrets(singleEncoded)
	// Single-encoded text won't decode twice to valid content
	// (the first decode succeeds but the raw text isn't valid base64)
	assert.Empty(t, result)
}

func TestParseDoubleBase64Secrets_BlankLines(t *testing.T) {
	secret := "blank-line-secret"
	firstEncode := base64.StdEncoding.EncodeToString([]byte(secret))
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(firstEncode))

	input := "\n\n" + doubleEncoded + "\n\n"
	result := ParseDoubleBase64Secrets(input)
	assert.Equal(t, []string{secret}, result)
}

func TestStripADOTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with timestamp",
			input:    "2026-02-24T15:18:41.1234567Z some content",
			expected: "some content",
		},
		{
			name:     "without timestamp",
			input:    "no timestamp here",
			expected: "no timestamp here",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripADOTimestamp(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
