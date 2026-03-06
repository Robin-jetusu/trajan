package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, kp)
	assert.NotNil(t, kp.PrivateKey)
	assert.NotNil(t, kp.PublicKey)

	// Verify it's a 4096-bit key
	assert.Equal(t, 4096, kp.PrivateKey.N.BitLen(), "RSA key must be 4096 bits")
}

func TestPublicKeyPEM(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	pemStr, err := kp.PublicKeyPEM()
	require.NoError(t, err)
	assert.NotEmpty(t, pemStr)

	// Verify PEM format
	assert.True(t, strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----"))
	assert.True(t, strings.Contains(pemStr, "-----END PUBLIC KEY-----"))

	// Verify it can be parsed back
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "should decode as valid PEM")
	assert.Equal(t, "PUBLIC KEY", block.Type)

	// Verify it's a valid public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, parsedKey)
}

func TestPrivateKeyPEM(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	pemStr := kp.PrivateKeyPEM()
	assert.NotEmpty(t, pemStr)

	// Verify PEM format
	assert.True(t, strings.HasPrefix(pemStr, "-----BEGIN RSA PRIVATE KEY-----"))
	assert.True(t, strings.Contains(pemStr, "-----END RSA PRIVATE KEY-----"))

	// Verify it can be parsed back
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "should decode as valid PEM")
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)

	// Verify it's a valid private key
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, 4096, parsedKey.N.BitLen())
}
