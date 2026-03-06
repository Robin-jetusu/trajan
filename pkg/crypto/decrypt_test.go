package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
)

// TestDecryptSecrets_EndToEnd simulates the complete encryption/decryption workflow
// for the secrets exfiltration attack.
func TestDecryptSecrets_EndToEnd(t *testing.T) {
	// Step 1: Generate RSA keypair (like the attack plugin would)
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	// Step 2: Simulate what happens in the GitHub Actions workflow
	// Create plaintext secrets JSON
	plaintext := []byte(`{"SECRET_KEY":"test-value","API_TOKEN":"secret-token"}`)

	// Generate random AES key (12 hex chars = 24 bytes hex string)
	aesKeyBytes := make([]byte, 12)
	_, err = rand.Read(aesKeyBytes)
	require.NoError(t, err)
	aesKeyHex := make([]byte, 24)
	for i, b := range aesKeyBytes {
		aesKeyHex[i*2] = "0123456789abcdef"[b>>4]
		aesKeyHex[i*2+1] = "0123456789abcdef"[b&0xF]
	}
	aesKeyStr := string(aesKeyHex)

	// Encrypt secrets with AES-256-CBC using OpenSSL format
	encryptedSecrets := encryptOpenSSLAES256CBC(t, plaintext, aesKeyStr)

	// Encrypt AES key with RSA public key (PKCS1v15)
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, kp.PublicKey, []byte(aesKeyStr))
	require.NoError(t, err)

	// Step 3: Decrypt using our implementation
	decrypted, err := DecryptSecrets(kp.PrivateKey, encryptedKey, encryptedSecrets)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptSecrets_InvalidFormat(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	tests := []struct {
		name          string
		encryptedData []byte
		expectedError string
	}{
		{
			name:          "too short",
			encryptedData: []byte("short"),
			expectedError: "encrypted data too short",
		},
		{
			name:          "missing Salted__ header",
			encryptedData: []byte("NotSaltedXXXXXXXXXXciphertext"),
			expectedError: "invalid OpenSSL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesKey := []byte("test-key")
			encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, kp.PublicKey, aesKey)

			_, err := DecryptSecrets(kp.PrivateKey, encryptedKey, tt.encryptedData)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestDecryptSecrets_WithNewlines(t *testing.T) {
	// The workflow adds newlines to the AES key, we should handle them
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	plaintext := []byte(`{"test":"value"}`)
	aesKeyStr := "abcdef0123456789abcdef01"

	// Encrypt secrets
	encryptedSecrets := encryptOpenSSLAES256CBC(t, plaintext, aesKeyStr)

	// Encrypt AES key with newline (like echo might add)
	aesKeyWithNewline := []byte(aesKeyStr + "\n")
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, kp.PublicKey, aesKeyWithNewline)
	require.NoError(t, err)

	// Should still decrypt correctly (newline should be stripped)
	decrypted, err := DecryptSecrets(kp.PrivateKey, encryptedKey, encryptedSecrets)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// encryptOpenSSLAES256CBC simulates OpenSSL's "openssl enc -aes-256-cbc -pbkdf2"
// This matches what the GitHub Actions workflow does.
func encryptOpenSSLAES256CBC(t *testing.T, plaintext []byte, password string) []byte {
	// Generate random salt
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	// Derive key and IV using PBKDF2 (same parameters as OpenSSL)
	derivedKey := pbkdf2.Key([]byte(password), salt, 10000, 48, sha256.New)
	key := derivedKey[:32]  // AES-256 key
	iv := derivedKey[32:48] // CBC IV

	// Add PKCS7 padding
	paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt with AES-256-CBC
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Format: "Salted__" + salt + ciphertext
	result := make([]byte, 0, 16+len(ciphertext))
	result = append(result, []byte("Salted__")...)
	result = append(result, salt...)
	result = append(result, ciphertext...)

	return result
}

// pkcs7Pad adds PKCS7 padding to data
func pkcs7Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = byte(paddingLen)
	}
	return append(data, padding...)
}

// TestDecryptSecrets_WrongBlockSize tests that decryption fails when ciphertext
// is not a multiple of AES block size (16 bytes).
func TestDecryptSecrets_WrongBlockSize(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	// Create ciphertext that's not a multiple of AES block size (16 bytes)
	// "Salted__" (8) + salt (8) + invalid ciphertext (5) = 21 bytes total
	invalidCiphertext := []byte("Salted__12345678short")

	aesKey := []byte("test-key-abcdef012345")
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, kp.PublicKey, aesKey)
	require.NoError(t, err)

	_, err = DecryptSecrets(kp.PrivateKey, encryptedKey, invalidCiphertext)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a multiple of block size")
}

// TestDecryptSecrets_InvalidRSAKey tests that decryption fails when using
// a different RSA key than what was used for encryption.
func TestDecryptSecrets_InvalidRSAKey(t *testing.T) {
	// Generate two different keypairs
	kp1, err := GenerateKeyPair()
	require.NoError(t, err)

	kp2, err := GenerateKeyPair()
	require.NoError(t, err)

	plaintext := []byte(`{"test":"value"}`)
	aesKeyStr := "abcdef0123456789abcdef01"

	// Encrypt secrets with keypair 1
	encryptedSecrets := encryptOpenSSLAES256CBC(t, plaintext, aesKeyStr)
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, kp1.PublicKey, []byte(aesKeyStr))
	require.NoError(t, err)

	// Try to decrypt with keypair 2 (wrong key)
	_, err = DecryptSecrets(kp2.PrivateKey, encryptedKey, encryptedSecrets)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting AES key")
}

// TestDecryptSecrets_CorruptedEncryptedKey tests that decryption fails when
// the encrypted AES key is corrupted or malformed.
func TestDecryptSecrets_CorruptedEncryptedKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	plaintext := []byte(`{"test":"value"}`)
	aesKeyStr := "abcdef0123456789abcdef01"
	encryptedSecrets := encryptOpenSSLAES256CBC(t, plaintext, aesKeyStr)

	tests := []struct {
		name         string
		encryptedKey []byte
	}{
		{
			name:         "empty encrypted key",
			encryptedKey: []byte{},
		},
		{
			name:         "corrupted encrypted key",
			encryptedKey: []byte("corrupted-data-not-valid-rsa"),
		},
		{
			name:         "truncated encrypted key",
			encryptedKey: []byte{0x00, 0x01, 0x02}, // Too short
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptSecrets(kp.PrivateKey, tt.encryptedKey, encryptedSecrets)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "decrypting AES key")
		})
	}
}

// TestDecryptSecrets_InvalidPadding tests that decryption fails when
// PKCS7 padding is invalid (inconsistent padding bytes).
func TestDecryptSecrets_InvalidPadding(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	aesKeyStr := "abcdef0123456789abcdef01"

	// Generate salt
	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	// Derive key and IV
	derivedKey := pbkdf2.Key([]byte(aesKeyStr), salt, 10000, 48, sha256.New)
	key := derivedKey[:32]
	iv := derivedKey[32:48]

	// Create plaintext with intentionally wrong padding
	// Valid padding would be all bytes set to the same value
	plaintext := []byte("test data")
	// Add invalid padding: last byte says padding length is 7, but bytes don't match
	invalidPadding := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	paddedData := append(plaintext, invalidPadding...)

	// Encrypt the invalid padded data
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)

	// Format as OpenSSL
	encryptedSecrets := make([]byte, 0, 16+len(ciphertext))
	encryptedSecrets = append(encryptedSecrets, []byte("Salted__")...)
	encryptedSecrets = append(encryptedSecrets, salt...)
	encryptedSecrets = append(encryptedSecrets, ciphertext...)

	// Encrypt AES key
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, kp.PublicKey, []byte(aesKeyStr))
	require.NoError(t, err)

	// Decryption should fail during padding removal
	_, err = DecryptSecrets(kp.PrivateKey, encryptedKey, encryptedSecrets)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "removing padding")
}

// TestPkcs7Unpad_EmptyData tests that pkcs7Unpad fails on empty input.
func TestPkcs7Unpad_EmptyData(t *testing.T) {
	_, err := pkcs7Unpad([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

// TestPkcs7Unpad_PaddingExceedsDataLength tests that pkcs7Unpad fails
// when the padding length value is greater than the data length.
func TestPkcs7Unpad_PaddingExceedsDataLength(t *testing.T) {
	// Data is 4 bytes, but last byte (padding length) says 10
	data := []byte{0x01, 0x02, 0x03, 0x0A}

	_, err := pkcs7Unpad(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "padding length exceeds data length")
}

// TestPkcs7Unpad_InvalidPaddingLength tests that pkcs7Unpad fails
// when padding length is 0 or greater than AES block size (16).
func TestPkcs7Unpad_InvalidPaddingLength(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		errorMsg string
	}{
		{
			name:     "padding length is 0",
			data:     []byte{0x01, 0x02, 0x03, 0x00},
			errorMsg: "invalid padding length",
		},
		{
			name:     "padding length > block size (17)",
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x11},
			errorMsg: "invalid padding length",
		},
		{
			name:     "padding length > block size (20)",
			data:     []byte{0x01, 0x02, 0x14},
			errorMsg: "invalid padding length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

// TestPkcs7Unpad_InconsistentPadding tests that pkcs7Unpad fails
// when not all padding bytes match the padding length.
func TestPkcs7Unpad_InconsistentPadding(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "last byte says 4 but first padding byte is wrong",
			data: []byte{0x01, 0x02, 0x03, 0x03, 0x04, 0x04, 0x04}, // Last 4 bytes (indices 3-6) should all be 0x04, but data[3] is 0x03
		},
		{
			name: "mixed padding values - first padding byte wrong",
			data: []byte{0x01, 0x02, 0x02, 0x03, 0x03}, // Last byte says 3, but data[2] is 0x02 not 0x03
		},
		{
			name: "mixed padding values - middle padding byte wrong",
			data: []byte{0x01, 0x02, 0x05, 0x03, 0x05, 0x05, 0x05}, // Says 5, but data[3] is 0x03 not 0x05
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid padding byte")
		})
	}
}
