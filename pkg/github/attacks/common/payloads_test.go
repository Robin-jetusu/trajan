package common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase64Roundtrip(t *testing.T) {
	testCases := []string{
		"hello world",
		"#!/bin/bash\necho hello",
		"",
		strings.Repeat("test", 1000),
	}

	for _, original := range testCases {
		encoded := EncodeBase64(original)
		decoded, err := DecodeBase64(encoded)

		assert.NoError(t, err)
		assert.Equal(t, original, decoded)
	}
}

func TestDecodeBase64_InvalidInput(t *testing.T) {
	_, err := DecodeBase64("not-valid-base64!!!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decoding base64")
}

func TestSecretsDumpPayload(t *testing.T) {
	// Without specific secrets
	payload := SecretsDumpPayload(nil)
	assert.Contains(t, payload, "name: Secrets Dump")
	assert.Contains(t, payload, "workflow_dispatch")
	assert.Contains(t, payload, "secrets.GITHUB_TOKEN")

	// With specific secrets
	payload = SecretsDumpPayload([]string{"MY_SECRET", "API_KEY"})
	assert.Contains(t, payload, "secrets.MY_SECRET")
	assert.Contains(t, payload, "secrets.API_KEY")
}

func TestPRAttackPayload(t *testing.T) {
	payload := PRAttackPayload("echo pwned")

	assert.Contains(t, payload, "pull_request_target")
	assert.Contains(t, payload, "echo pwned")
	assert.Contains(t, payload, "github.event.pull_request.head.sha")
}

func TestEncryptedSecretsDumpPayload(t *testing.T) {
	pubKey := `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
-----END PUBLIC KEY-----`
	branchName := "test-branch"

	payload := EncryptedSecretsDumpPayload(pubKey, branchName)

	// Verify workflow structure
	assert.Contains(t, payload, "name: "+branchName)
	assert.Contains(t, payload, "on:")
	assert.Contains(t, payload, "push:")
	assert.Contains(t, payload, "branches:")
	assert.Contains(t, payload, branchName)

	// Verify secrets dump step
	assert.Contains(t, payload, "toJSON(secrets)")
	assert.Contains(t, payload, "output.json")

	// Verify encryption step
	assert.Contains(t, payload, "openssl rand -hex 12")
	assert.Contains(t, payload, "openssl enc -aes-256-cbc -pbkdf2")
	assert.Contains(t, payload, "openssl pkeyutl -encrypt")
	assert.Contains(t, payload, "output_updated.json")
	assert.Contains(t, payload, "lookup.txt")

	// Verify public key is embedded
	assert.Contains(t, payload, "PUBKEY:")
	assert.Contains(t, payload, "BEGIN PUBLIC KEY")

	// Verify artifact upload
	assert.Contains(t, payload, "actions/upload-artifact")
	assert.Contains(t, payload, "name: files")
	assert.Contains(t, payload, "output_updated.json")
	assert.Contains(t, payload, "lookup.txt")
}

func TestEncryptedSecretsDumpPayloadBase64(t *testing.T) {
	pubKey := `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
-----END PUBLIC KEY-----`
	branchName := "test-branch"

	encoded := EncryptedSecretsDumpPayloadBase64(pubKey, branchName)

	// Verify it's base64 encoded
	assert.NotEmpty(t, encoded)

	// Decode and verify contents
	decoded, err := DecodeBase64(encoded)
	assert.NoError(t, err)
	assert.Contains(t, decoded, "toJSON(secrets)")
	assert.Contains(t, decoded, "openssl")
	assert.Contains(t, decoded, branchName)
}
