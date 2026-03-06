package gitlab

import (
	"fmt"
	"regexp"
	"strings"
)

// RunnerLogInfo holds runner details extracted from job logs
type RunnerLogInfo struct {
	RunnerName   string
	MachineName  string
	Version      string
	Executor     string
	Platform     string
	Tags         []string
	IsSelfHosted bool
}

var (
	// Regex patterns for extracting runner information from GitLab job traces
	runnerNamePattern1 = regexp.MustCompile(`Running with gitlab-runner ([\d\.]+) \([a-f0-9]+\) on (.+?) \(`)
	runnerNamePattern2 = regexp.MustCompile(`Running on (.+?) via`)
	machineNamePattern = regexp.MustCompile(`Running on (.+?) via GitLab Runner`)
	executorPattern    = regexp.MustCompile(`Executor: (.+)`)

	// GitLab SaaS shared runner patterns
	saasRunnerPatterns = []string{
		"saas-linux",
		"saas-macos",
		"saas-windows",
		"shared-gitlab-org",
		"runners-manager.gitlab.com",
	}
)

// ParseJobTrace extracts runner information from job log content
func ParseJobTrace(traceContent string) (*RunnerLogInfo, error) {
	if traceContent == "" {
		return nil, fmt.Errorf("empty trace content")
	}

	info := &RunnerLogInfo{
		IsSelfHosted: true, // Default to self-hosted, mark false if SaaS patterns found
	}

	lines := strings.Split(traceContent, "\n")

	// Extract runner name and version
	for _, line := range lines {
		// Pattern 1: "Running with gitlab-runner X.Y.Z (hash) on RUNNER-NAME (hash)"
		if matches := runnerNamePattern1.FindStringSubmatch(line); len(matches) >= 3 {
			info.Version = matches[1]
			info.RunnerName = matches[2]
			break
		}
	}

	// Extract machine name
	for _, line := range lines {
		if matches := machineNamePattern.FindStringSubmatch(line); len(matches) >= 2 {
			info.MachineName = matches[1]
			break
		}
	}

	// If no machine name found, try alternative pattern
	if info.MachineName == "" {
		for _, line := range lines {
			if matches := runnerNamePattern2.FindStringSubmatch(line); len(matches) >= 2 {
				candidate := matches[1]
				// Avoid matching runner pod names (Kubernetes pattern)
				if !strings.Contains(candidate, "runner-pod-") {
					info.MachineName = candidate
					break
				}
			}
		}
	}

	// Extract executor
	for _, line := range lines {
		if matches := executorPattern.FindStringSubmatch(line); len(matches) >= 2 {
			info.Executor = strings.TrimSpace(matches[1])
			break
		}
	}

	// Determine if self-hosted by checking for SaaS patterns
	runnerDesc := strings.ToLower(info.RunnerName)
	for _, pattern := range saasRunnerPatterns {
		if strings.Contains(runnerDesc, pattern) {
			info.IsSelfHosted = false
			break
		}
	}

	// Validate we extracted at least runner name
	if info.RunnerName == "" {
		return nil, fmt.Errorf("could not extract runner name from trace")
	}

	return info, nil
}
