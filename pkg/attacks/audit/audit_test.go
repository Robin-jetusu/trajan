package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestAuditLog(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	entry := AuditEntry{
		SessionID: "test-session",
		Plugin:    "test-plugin",
		Target:    platforms.Target{Value: "owner/repo"},
		Action:    "test_action",
		DryRun:    true,
		Result:    "success",
	}

	err := Log(entry)
	assert.NoError(t, err)

	// Verify file created and contains entry
	auditPath := filepath.Join(tmpDir, ".trajan", "audit.jsonl")
	data, err := os.ReadFile(auditPath)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "test-session")
	assert.Contains(t, string(data), "test-plugin")
}

func TestLogAttackStartEnd(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	target := platforms.Target{Value: "owner/repo"}

	// Log start
	LogAttackStart("session-1", "test-plugin", target, false)

	// Log end
	result := &attacks.AttackResult{
		Plugin:  "test-plugin",
		Success: true,
		Message: "completed",
	}
	LogAttackEnd("session-1", "test-plugin", target, result)

	// Verify both entries in file
	auditPath := filepath.Join(tmpDir, ".trajan", "audit.jsonl")
	data, err := os.ReadFile(auditPath)
	assert.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, 2)
	assert.Contains(t, lines[0], "attack_start")
	assert.Contains(t, lines[1], "attack_end")
}
