package persistence

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// generateSSHKeyPair generates a 2048-bit RSA SSH key pair
// Returns (publicKey, privateKey, error)
func generateSSHKeyPair() (string, string, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generating RSA key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Generate public key in SSH format
	sshPublicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("generating SSH public key: %w", err)
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)

	return string(publicKeyBytes), string(privateKeyBytes), nil
}
