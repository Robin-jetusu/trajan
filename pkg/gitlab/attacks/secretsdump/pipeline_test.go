// pkg/gitlab/attacks/secretsdump/pipeline_test.go
package secretsdump

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestGeneratePipelineYAML(t *testing.T) {
	publicKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`

	yamlContent := GeneratePipelineYAML(publicKeyPEM)

	// Should be valid YAML
	var pipeline map[string]interface{}
	err := yaml.Unmarshal([]byte(yamlContent), &pipeline)
	assert.NoError(t, err)

	// Check structure
	assert.Contains(t, pipeline, "stages")
	assert.Contains(t, pipeline, "default")
	assert.Contains(t, pipeline, "variables")
	assert.Contains(t, pipeline, "build_job")

	// Check variables contains KEY
	variables := pipeline["variables"].(map[string]interface{})
	assert.Contains(t, variables, "KEY")

	// Check default image is alpine
	defaultCfg := pipeline["default"].(map[string]interface{})
	assert.Equal(t, "alpine", defaultCfg["image"])

	// Check build_job contains encryption script
	buildJob := pipeline["build_job"].(map[string]interface{})
	script := buildJob["script"].([]interface{})

	scriptStr := ""
	for _, line := range script {
		scriptStr += line.(string) + "\n"
	}

	// Should contain OpenSSL commands
	assert.Contains(t, scriptStr, "openssl")
	assert.Contains(t, scriptStr, "rand")
	assert.Contains(t, scriptStr, "pkeyutl -encrypt")
	assert.Contains(t, scriptStr, "enc -aes-256-cbc")
	assert.Contains(t, scriptStr, "pbkdf2")
}

func TestGeneratePipelineYAMLContainsPublicKey(t *testing.T) {
	publicKeyPEM := "TEST-PUBLIC-KEY-DATA"

	yamlContent := GeneratePipelineYAML(publicKeyPEM)

	// Public key should be embedded in YAML
	assert.Contains(t, yamlContent, publicKeyPEM)
}
