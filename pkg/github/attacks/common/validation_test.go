package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePayload_ValidPayloads(t *testing.T) {
	testCases := []struct {
		name    string
		payload string
	}{
		{"simple command", "echo hello"},
		{"multiline script", "#!/bin/bash\necho hello\nexit 0"},
		{"empty payload", ""},
		{"max size payload", strings.Repeat("a", MaxPayloadSize)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(tc.payload)
			assert.NoError(t, err)
		})
	}
}

func TestValidatePayload_InvalidPayloads(t *testing.T) {
	testCases := []struct {
		name        string
		payload     string
		errContains string
	}{
		{
			name:        "exceeds max size",
			payload:     strings.Repeat("a", MaxPayloadSize+1),
			errContains: "exceeds maximum size",
		},
		{
			name:        "contains null bytes",
			payload:     "echo \x00 hello",
			errContains: "null bytes",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(tc.payload)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}
