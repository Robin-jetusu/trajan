package common

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateBranchName_Format(t *testing.T) {
	sessionID := "a3f5b2c8d1e4"
	branchName := GenerateBranchName(sessionID)

	// Should match: prefix/topic-shortid
	pattern := `^(feature|bugfix|hotfix|fix|update|patch)/(deps|tests|ci|config|build|lint|security|docs)-[a-z0-9]{6}$`
	assert.Regexp(t, regexp.MustCompile(pattern), branchName)
}

func TestGenerateBranchName_Deterministic(t *testing.T) {
	sessionID := "test123"

	branch1 := GenerateBranchName(sessionID)
	branch2 := GenerateBranchName(sessionID)

	assert.Equal(t, branch1, branch2, "Same session ID should generate same branch name")
}

func TestGenerateBranchName_ShortID(t *testing.T) {
	longSessionID := "a3f5b2c8d1e4f7g9"
	branchName := GenerateBranchName(longSessionID)

	// Should use first 6 chars: a3f5b2
	assert.Contains(t, branchName, "a3f5b2")
	assert.NotContains(t, branchName, "c8d1e4")
}

func TestGenerateBranchNameNoTrajanIoC(t *testing.T) {
	sessionID := "a3f5b29e-1234-5678-90ab-cdef12345678"

	name := GenerateBranchName(sessionID)

	// CRITICAL OpSec check: no "trajan" in branch name
	assert.NotContains(t, strings.ToLower(name), "trajan")
	assert.NotContains(t, strings.ToLower(name), "attack")
	assert.NotContains(t, strings.ToLower(name), "secrets")
	assert.NotContains(t, strings.ToLower(name), "dump")
}

func TestGenerateBranchName_UUIDFormat(t *testing.T) {
	sessionID := "a3f5b29e-1234-5678-90ab-cdef12345678"

	name := GenerateBranchName(sessionID)

	// Should have format: prefix/suffix
	parts := strings.Split(name, "/")
	assert.Len(t, parts, 2, "Should have format prefix/suffix")

	prefix := parts[0]
	suffix := parts[1]

	// Check prefix is realistic
	validPrefixes := []string{"feature", "bugfix", "hotfix", "fix", "update", "patch"}
	assert.Contains(t, validPrefixes, prefix)

	// Check suffix format: topic-shortID
	suffixParts := strings.Split(suffix, "-")
	assert.Len(t, suffixParts, 2, "Suffix should be topic-shortID")

	topic := suffixParts[0]
	shortID := suffixParts[1]

	validTopics := []string{"deps", "tests", "ci", "config", "build", "lint", "security", "docs"}
	assert.Contains(t, validTopics, topic)

	assert.Len(t, shortID, 6)
	assert.Equal(t, sessionID[:6], shortID)
}
