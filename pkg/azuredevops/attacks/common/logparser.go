package common

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// adoTimestampPattern matches the ISO 8601 timestamp prefix that Azure DevOps
// prepends to every build log line (e.g. "2026-02-24T15:18:41.1234567Z ").
var adoTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*`)

// stripADOTimestamp removes the Azure DevOps timestamp prefix from a log line.
func stripADOTimestamp(line string) string {
	return adoTimestampPattern.ReplaceAllString(line, "")
}

// ParseDoubleBase64Secrets extracts double-base64-encoded secrets from build log output.
// The extraction pipelines encode secrets as: value | base64 | base64
// to bypass Azure DevOps secret masking in logs.
// Used by agentexec for capturing arbitrary command output from self-hosted agent pipelines.
func ParseDoubleBase64Secrets(logContent string) []string {
	secrets := []string{} // Initialize to empty slice, not nil

	lines := strings.Split(logContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = stripADOTimestamp(line)
		if line == "" {
			continue
		}

		// Try to decode first layer
		firstDecode, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}

		// Try to decode second layer
		secondDecode, err := base64.StdEncoding.DecodeString(string(firstDecode))
		if err != nil {
			continue
		}

		// Successfully double-decoded
		secrets = append(secrets, string(secondDecode))
	}

	return secrets
}
