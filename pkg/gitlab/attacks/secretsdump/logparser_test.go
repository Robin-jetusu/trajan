// pkg/gitlab/attacks/secretsdump/logparser_test.go
package secretsdump

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractEncryptedBlobs(t *testing.T) {
	// Realistic log with large base64 chunks (>500 chars) like real GitLab CI
	symkeyChunk := strings.Repeat("A", 684)   // RSA-4096 encrypted = 684 base64 chars
	secretsChunk := strings.Repeat("B", 7680) // Encrypted env vars

	logs := fmt.Sprintf(`
$ apk add openssl
$ openssl rand -base64 24 > sym.key
$ echo -n '$'; cat sym.key | openssl pkeyutl -encrypt ... | base64 -w 0; echo -n '$'; env | openssl enc -aes-256-cbc ... | base64 -w 0; echo '$'
$%s$%s$
Job succeeded
`, symkeyChunk, secretsChunk)

	encSymKey, encSecrets, err := ExtractEncryptedBlobs(logs)

	assert.NoError(t, err)
	assert.Equal(t, symkeyChunk, encSymKey)
	assert.Equal(t, secretsChunk, encSecrets)
}

func TestExtractEncryptedBlobsNoMatch(t *testing.T) {
	logs := `Job failed: command not found`

	_, _, err := ExtractEncryptedBlobs(logs)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted blobs not found")
}

func TestExtractEncryptedBlobsMultipleMatches(t *testing.T) {
	// With chunk-based extraction, we find the largest chunks
	chunk1 := strings.Repeat("A", 684)
	chunk2 := strings.Repeat("B", 7680)
	chunk3 := strings.Repeat("C", 2000) // Smaller chunk (junk)

	logs := fmt.Sprintf(`
Some logs
%s
More logs
%s
Even more
%s
End`, chunk1, chunk2, chunk3)

	// Should extract first two large chunks
	encSymKey, encSecrets, err := ExtractEncryptedBlobs(logs)

	assert.NoError(t, err)
	assert.Equal(t, chunk1, encSymKey)
	assert.Equal(t, chunk2, encSecrets)
}
