package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test list subcommands - now called directly as top-level enumerate subcommands
func TestListReposCommandExists(t *testing.T) {
	cmd := newReposCmd()
	assert.Equal(t, "repos", cmd.Use)
}

func TestListUsersCommandExists(t *testing.T) {
	cmd := newUsersCmd()
	assert.Equal(t, "users", cmd.Use)
}

func TestListGroupsCommandExists(t *testing.T) {
	cmd := newGroupsCmd()
	assert.Equal(t, "groups", cmd.Use)
}

func TestListPipelinesCommandExists(t *testing.T) {
	cmd := newPipelinesCmd()
	assert.Equal(t, "pipelines", cmd.Use)
}

func TestListVariablesCommandExists(t *testing.T) {
	cmd := newVariableGroupsCmd()
	assert.Equal(t, "variable-groups", cmd.Use)
}

func TestListConnectionsCommandExists(t *testing.T) {
	cmd := newConnectionsCmd()
	assert.Equal(t, "connections", cmd.Use)
}

func TestListAgentPoolsCommandExists(t *testing.T) {
	cmd := newAgentPoolsCmd()
	assert.Equal(t, "agent-pools", cmd.Use)
}

func TestListSecretsCommandExists(t *testing.T) {
	cmd := newSecureFilesCmd()
	assert.Equal(t, "secure-files", cmd.Use)
}

// Test search subcommands
func TestSearchCodeCommandExists(t *testing.T) {
	cmd := newSearchCmd()
	found, _, err := cmd.Find([]string{"code"})
	assert.NoError(t, err)
	assert.Equal(t, "code", found.Use)
}

func TestSearchCredsCommandExists(t *testing.T) {
	cmd := newSearchCmd()
	found, _, err := cmd.Find([]string{"creds"})
	assert.NoError(t, err)
	assert.Equal(t, "creds", found.Use)
}

func TestSearchLogsCommandExists(t *testing.T) {
	cmd := newSearchCmd()
	found, _, err := cmd.Find([]string{"logs"})
	assert.NoError(t, err)
	assert.Equal(t, "logs", found.Use)
}

func TestSearchFilesCommandExists(t *testing.T) {
	cmd := newSearchCmd()
	found, _, err := cmd.Find([]string{"files"})
	assert.NoError(t, err)
	assert.Equal(t, "files", found.Use)
}
