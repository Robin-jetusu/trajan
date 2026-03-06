package runnerexec

import (
	"fmt"
	"strings"
)

// GeneratePipelineYAML generates .gitlab-ci.yml for command execution
// Targets runners with specified tags and base64-encodes output
func GeneratePipelineYAML(runnerTags []string, command string) (string, error) {
	// Validate inputs
	if len(runnerTags) == 0 {
		return "", fmt.Errorf("runnerTags cannot be empty")
	}
	if command == "" {
		return "", fmt.Errorf("command cannot be empty")
	}
	if strings.ContainsAny(command, "\n\r") {
		return "", fmt.Errorf("command cannot contain line breaks: %q", command)
	}

	// Validate runner tags don't contain line breaks (breaks YAML structure)
	for _, tag := range runnerTags {
		if strings.ContainsAny(tag, "\n\r") {
			return "", fmt.Errorf("runner tags cannot contain line breaks: %q", tag)
		}
	}

	// Build tags list
	var tagsYAML strings.Builder
	for _, tag := range runnerTags {
		tagsYAML.WriteString(fmt.Sprintf("    - %s\n", tag))
	}

	return fmt.Sprintf(`runner-exec-job:
  tags:
%s  script:
    - (%s) 2>&1 | base64 || true
`, tagsYAML.String(), command), nil
}
