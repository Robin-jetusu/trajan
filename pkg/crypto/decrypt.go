package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// DecryptSecrets decrypts secrets encrypted by the exfiltration workflow.
//
// The encryption scheme used in the GitHub Actions workflow:
// 1. Generate random AES key (12 hex chars = 24 bytes hex string)
// 2. Encrypt secrets JSON with OpenSSL AES-256-CBC + PBKDF2
// 3. Encrypt AES key with RSA public key (PKCS1v15)
//
// The decryption scheme:
// 1. Decrypt AES key with RSA private key (PKCS1v15)
// 2. Extract salt from encrypted file (bytes 8-16, after "Salted__" prefix)
// 3. Derive key+IV from password using PBKDF2 (SHA256, 10000 iterations, 48 bytes)
// 4. Decrypt with AES-256-CBC
// 5. Remove PKCS7 padding
func DecryptSecrets(privateKey *rsa.PrivateKey, encryptedKey, encryptedSecrets []byte) ([]byte, error) {
	// Step 1: Decrypt the AES key with RSA (PKCS1v15 padding)
	symKey, err := rsa.DecryptPKCS1v15(nil, privateKey, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting AES key: %w", err)
	}

	// Remove any trailing newline or whitespace from the key
	// (the workflow might add newlines via echo)
	symKeyStr := strings.TrimSpace(string(symKey))

	// Step 2: Parse OpenSSL encrypted format
	// Format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext
	if len(encryptedSecrets) < 16 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Check for "Salted__" magic header
	if string(encryptedSecrets[:8]) != "Salted__" {
		return nil, fmt.Errorf("invalid OpenSSL format: missing Salted__ header")
	}

	salt := encryptedSecrets[8:16]
	ciphertext := encryptedSecrets[16:]

	// Step 3: Derive key and IV using PBKDF2
	// OpenSSL uses SHA256 with 10000 iterations for PBKDF2
	// Key (32 bytes) + IV (16 bytes) = 48 bytes total
	derivedKey := pbkdf2.Key([]byte(symKeyStr), salt, 10000, 48, sha256.New)
	key := derivedKey[:32]  // AES-256 key
	iv := derivedKey[32:48] // CBC IV

	// Step 4: Decrypt with AES-256-CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Step 5: Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("removing padding: %w", err)
	}

	return plaintext, nil
}

// pkcs7Unpad removes PKCS7 padding from decrypted data.
// pkcs7Unpad removes PKCS7 padding: cleartext[: -cleartext[-1]]
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	// Get padding length from last byte
	paddingLen := int(data[len(data)-1])

	// Validate padding length
	if paddingLen == 0 || paddingLen > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}

	if paddingLen > len(data) {
		return nil, fmt.Errorf("padding length exceeds data length")
	}

	// Verify all padding bytes are the same
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding byte at position %d", i)
		}
	}

	return data[:len(data)-paddingLen], nil
}
