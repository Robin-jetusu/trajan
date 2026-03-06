package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTransport_NoProxy(t *testing.T) {
	config := Config{}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.Nil(t, transport)
}

func TestNewTransport_HTTPProxy(t *testing.T) {
	config := Config{
		HTTPProxy: "http://proxy.example.com:8080",
	}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewTransport_SOCKSProxy(t *testing.T) {
	config := Config{
		SOCKSProxy: "socks5://proxy.example.com:1080",
	}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewTransport_BothProxiesError(t *testing.T) {
	config := Config{
		HTTPProxy:  "http://proxy.example.com:8080",
		SOCKSProxy: "socks5://proxy.example.com:1080",
	}
	transport, err := NewTransport(config)
	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "cannot use both HTTP and SOCKS proxy simultaneously")
}

func TestNewTransport_SkipTLSVerify(t *testing.T) {
	config := Config{
		SkipTLSVerify: true,
	}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewTransport_HTTPProxyWithTLSSkip(t *testing.T) {
	config := Config{
		HTTPProxy:     "http://proxy.example.com:8080",
		SkipTLSVerify: true,
	}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewTransport_InvalidHTTPProxyURL(t *testing.T) {
	config := Config{
		HTTPProxy: "://invalid-url",
	}
	transport, err := NewTransport(config)
	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "parsing HTTP proxy URL")
}

func TestNewTransport_InvalidSOCKSProxyURL(t *testing.T) {
	config := Config{
		SOCKSProxy: "://invalid-url",
	}
	transport, err := NewTransport(config)
	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Contains(t, err.Error(), "parsing SOCKS proxy URL")
}

func TestNewTransport_SOCKSProxyWithAuth(t *testing.T) {
	config := Config{
		SOCKSProxy: "socks5://user:pass@proxy.example.com:1080",
	}
	transport, err := NewTransport(config)
	require.NoError(t, err)
	assert.NotNil(t, transport)
}
