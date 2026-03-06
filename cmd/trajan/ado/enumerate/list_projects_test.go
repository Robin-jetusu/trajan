package enumerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListProjectsCommandExists(t *testing.T) {
	projectsCmd := newProjectsCmd()
	require.NotNil(t, projectsCmd)
	assert.Equal(t, "projects", projectsCmd.Use)
}
