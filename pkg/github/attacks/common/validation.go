package common

import (
	"fmt"
	"strings"
)

const MaxPayloadSize = 1024 * 1024 // 1MB

// ValidatePayload checks if a payload is safe to use
func ValidatePayload(payload string) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("payload exceeds maximum size of %d bytes", MaxPayloadSize)
	}

	if strings.Contains(payload, "\x00") {
		return fmt.Errorf("payload contains null bytes")
	}

	// Additional validation can be added here

	return nil
}
