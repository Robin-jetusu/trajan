// pkg/gitlab/attacks/secretsdump/logparser.go
package secretsdump

import (
	"fmt"
	"regexp"
)

// ExtractEncryptedBlobs extracts the encrypted symmetric key and secrets from pipeline logs
// Expected format: $<base64_enc_symkey>$<base64_enc_secrets>$
// GitLab CI adds timestamps/ANSI codes that break the pattern, so we find large base64 chunks
func ExtractEncryptedBlobs(logs string) (encSymKey, encSecrets string, err error) {
	// Find all continuous base64 strings longer than 500 chars
	// Encrypted symkey is ~684 chars (RSA-4096), encrypted secrets are much larger
	pattern := regexp.MustCompile(`[A-Za-z0-9+/=]{500,}`)

	matches := pattern.FindAllString(logs, -1)
	if len(matches) < 2 {
		return "", "", fmt.Errorf("encrypted blobs not found in logs (need 2 large base64 chunks, found %d)", len(matches))
	}

	// First large chunk is the encrypted symmetric key (~684 chars)
	encSymKey = matches[0]

	// Second large chunk is the encrypted secrets
	// NOTE: GitLab logs may break output, but chunk 2+ is usually log artifacts, not continuation
	// The original approach (using only matches[1]) was correct
	encSecrets = matches[1]

	return encSymKey, encSecrets, nil
}
