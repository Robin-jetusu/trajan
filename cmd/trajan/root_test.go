package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyFlag(t *testing.T) {
	// Verify the --proxy flag exists and defaults to empty string
	cmd := rootCmd
	flag := cmd.PersistentFlags().Lookup("proxy")
	assert.NotNil(t, flag, "--proxy flag should exist")
	assert.Equal(t, "", flag.DefValue, "--proxy should default to empty string")
}

func TestSOCKSProxyFlag(t *testing.T) {
	// Verify the --socks-proxy flag exists and defaults to empty string
	cmd := rootCmd
	flag := cmd.PersistentFlags().Lookup("socks-proxy")
	assert.NotNil(t, flag, "--socks-proxy flag should exist")
	assert.Equal(t, "", flag.DefValue, "--socks-proxy should default to empty string")
}
