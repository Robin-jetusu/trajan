// pkg/gitlab/attacks/secretsdump/crypto.go
package secretsdump

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// DecryptSecrets decrypts the encrypted environment variables using
// RSA-4096 + AES-256-CBC + PBKDF2 matching OpenSSL defaults
func DecryptSecrets(privateKey *rsa.PrivateKey, encSymKeyB64, encSecretsB64 string) ([]byte, error) {
	// 1. Base64 decode the blobs
	encSymKey, err := base64.StdEncoding.DecodeString(encSymKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding symmetric key: %w", err)
	}

	encSecrets, err := base64.StdEncoding.DecodeString(encSecretsB64)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted secrets: %w", err)
	}

	// 2. Decrypt symmetric key using RSA private key (PKCS1v15)
	symKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encSymKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting symmetric key: %w", err)
	}

	// 3. Extract salt from OpenSSL format
	// OpenSSL enc format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext
	if len(encSecrets) < 16 {
		return nil, fmt.Errorf("encrypted secrets too short (need at least 16 bytes, got %d)", len(encSecrets))
	}

	if string(encSecrets[:8]) != "Salted__" {
		return nil, fmt.Errorf("invalid OpenSSL format (missing 'Salted__' header, got: %q)", string(encSecrets[:8]))
	}

	salt := encSecrets[8:16]
	ciphertext := encSecrets[16:]

	// 4. Derive AES key and IV using PBKDF2
	// Matches OpenSSL's default: SHA256, 10000 iterations, 48 bytes (32 key + 16 IV)
	derived := pbkdf2.Key(symKey, salt, 10000, 48, sha256.New)
	aesKey := derived[:32] // AES-256 key
	iv := derived[32:48]   // AES IV (16 bytes)

	// 5. Decrypt with AES-256-CBC
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 6. Remove PKCS7 padding
	plaintext, err = removePKCS7Padding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("removing padding: %w", err)
	}

	return plaintext, nil
}

// removePKCS7Padding removes PKCS7 padding from plaintext
func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	paddingLen := int(data[len(data)-1])

	// Sanity check only
	if paddingLen > len(data) {
		return nil, fmt.Errorf("invalid padding length: %d (data length: %d)", paddingLen, len(data))
	}

	// Minimal padding validation for compatibility with OpenSSL output
	// Trust the last byte value and remove that many bytes
	if paddingLen == 0 {
		return data, nil
	}

	return data[:len(data)-paddingLen], nil
}

// ParseSecretsFromEnv parses KEY=VALUE pairs from decrypted env output
func ParseSecretsFromEnv(envOutput []byte) map[string]string {
	secrets := make(map[string]string)
	lines := strings.Split(string(envOutput), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split on first '=' only
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Filter out common system variables
		if isSystemEnvVar(key) {
			continue
		}

		secrets[key] = value
	}

	return secrets
}

// isSystemEnvVar checks if a variable is a system variable to filter out
func isSystemEnvVar(key string) bool {
	systemVars := []string{
		"PATH", "HOME", "USER", "SHELL", "PWD", "LANG",
		"TERM", "SHLVL", "OLDPWD", "HOSTNAME",
	}

	for _, v := range systemVars {
		if key == v {
			return true
		}
	}

	return false
}
