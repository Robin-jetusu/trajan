package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchCommandExists(t *testing.T) {
	cmd := rootCmd
	searchCmd, _, err := cmd.Find([]string{"search"})
	assert.NoError(t, err, "search subcommand should exist")
	assert.NotNil(t, searchCmd, "search subcommand should not be nil")
	assert.Equal(t, "search", searchCmd.Name(), "subcommand name should be 'search'")
}

func TestSearchProviderFlag(t *testing.T) {
	cmd := rootCmd
	searchCmd, _, _ := cmd.Find([]string{"search"})
	flag := searchCmd.Flags().Lookup("provider")
	assert.NotNil(t, flag, "--provider flag should exist")
	assert.Equal(t, "sourcegraph", flag.DefValue, "--provider should default to 'sourcegraph'")
}

func TestSearchOrgFlag(t *testing.T) {
	cmd := rootCmd
	searchCmd, _, _ := cmd.Find([]string{"search"})
	flag := searchCmd.Flags().Lookup("org")
	assert.NotNil(t, flag, "--org flag should exist")
	assert.Equal(t, "", flag.DefValue, "--org should default to empty string")
}

func TestSearchQueryFlag(t *testing.T) {
	cmd := rootCmd
	searchCmd, _, _ := cmd.Find([]string{"search"})
	flag := searchCmd.Flags().Lookup("query")
	assert.NotNil(t, flag, "--query flag should exist")
	assert.Equal(t, "", flag.DefValue, "--query should default to empty string")
}

func TestSearchOutputFileFlag(t *testing.T) {
	cmd := rootCmd
	searchCmd, _, _ := cmd.Find([]string{"search"})
	flag := searchCmd.Flags().Lookup("output-file")
	assert.NotNil(t, flag, "--output-file flag should exist")
	assert.Equal(t, "", flag.DefValue, "--output-file should default to empty string")
}
