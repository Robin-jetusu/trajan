package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyPair contains an RSA key pair for secrets encryption.
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// GenerateKeyPair generates a 4096-bit RSA key pair.
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PublicKeyPEM returns the public key in PEM format (SubjectPublicKeyInfo).
// This format is compatible with OpenSSL's -pubin flag.
func (kp *KeyPair) PublicKeyPEM() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(pubKeyPEM), nil
}

// PrivateKeyPEM returns the private key in PEM format (PKCS1).
// This format is compatible with OpenSSL's pkeyutl command.
func (kp *KeyPair) PrivateKeyPEM() string {
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(kp.PrivateKey),
	})

	return string(privKeyPEM)
}
