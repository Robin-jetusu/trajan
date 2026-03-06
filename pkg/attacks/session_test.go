package attacks

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestNewSession(t *testing.T) {
	target := platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"}

	session := NewSession("test-id", target, "github", "")

	assert.Equal(t, "test-id", session.ID)
	assert.Equal(t, target, session.Target)
	assert.NotZero(t, session.CreatedAt)
	assert.NotNil(t, session.Results)
	assert.Len(t, session.Results, 0)
}

func TestSession_AddResult(t *testing.T) {
	session := NewSession("test-id", platforms.Target{Value: "owner/repo"}, "github", "")

	result1 := &AttackResult{Plugin: "plugin1", Success: true}
	result2 := &AttackResult{Plugin: "plugin2", Success: false}

	session.AddResult(result1)
	assert.Len(t, session.Results, 1)

	session.AddResult(result2)
	assert.Len(t, session.Results, 2)

	assert.Equal(t, "plugin1", session.Results[0].Plugin)
	assert.Equal(t, "plugin2", session.Results[1].Plugin)
}

func TestSession_SaveLoad(t *testing.T) {
	// Setup temp directory
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	target := platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"}
	session := NewSession("save-load-test", target, "github", "")
	session.AddResult(&AttackResult{
		Plugin:    "test-plugin",
		Success:   true,
		Message:   "test message",
		SessionID: "save-load-test",
	})

	// Save
	err := session.Save()
	assert.NoError(t, err)

	// Load
	loaded, err := LoadSession("save-load-test")
	assert.NoError(t, err)
	assert.Equal(t, session.ID, loaded.ID)
	assert.Equal(t, session.Target, loaded.Target)
	assert.Len(t, loaded.Results, 1)
	assert.Equal(t, "test-plugin", loaded.Results[0].Plugin)
}

func TestSession_Delete(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	session := NewSession("delete-test", platforms.Target{Value: "owner/repo"}, "github", "")

	// Save first
	err := session.Save()
	assert.NoError(t, err)

	// Verify exists
	_, err = LoadSession("delete-test")
	assert.NoError(t, err)

	// Delete
	err = session.Delete()
	assert.NoError(t, err)

	// Verify gone
	_, err = LoadSession("delete-test")
	assert.Error(t, err)
}

func TestListSessions(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		session := NewSession(fmt.Sprintf("list-test-%d", i), platforms.Target{Value: "owner/repo"}, "github", "")
		session.AddResult(&AttackResult{Plugin: "test", Artifacts: []Artifact{{Type: ArtifactBranch}}})
		err := session.Save()
		assert.NoError(t, err)
	}

	// List
	summaries, err := ListSessions()
	assert.NoError(t, err)
	assert.Len(t, summaries, 3)

	// Verify artifact count calculated
	for _, s := range summaries {
		assert.Equal(t, 1, s.ArtifactCount)
	}
}

func TestLoadSession_NotFound(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	_, err := LoadSession("nonexistent-session")
	assert.Error(t, err)
}
