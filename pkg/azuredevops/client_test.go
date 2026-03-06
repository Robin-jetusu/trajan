package azuredevops

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClient tests client initialization with defaults
func TestNewClient(t *testing.T) {
	orgURL := "https://dev.azure.com/test-org"
	pat := "test-token-12345"

	client := NewClient(orgURL, pat)

	require.NotNil(t, client)
	assert.NotNil(t, client.httpClient)
	assert.NotNil(t, client.rateLimiter)
	assert.NotNil(t, client.semaphore)
	assert.Equal(t, orgURL, client.orgURL)
	// Don't expose token in assertions (security)
}

// TestNewClient_WithOptions tests client with functional options
func TestNewClient_WithOptions(t *testing.T) {
	orgURL := "https://dev.azure.com/test-org"
	pat := "test-token"
	timeout := 60 * time.Second
	concurrency := int64(50)

	client := NewClient(orgURL, pat,
		WithTimeout(timeout),
		WithConcurrency(concurrency),
	)

	require.NotNil(t, client)
	assert.Equal(t, timeout, client.httpClient.Timeout)
	// Semaphore internal state not directly testable, but creation shouldn't panic
}

// TestNewClient_DefaultValues tests default values when no options provided
func TestNewClient_DefaultValues(t *testing.T) {
	client := NewClient("https://dev.azure.com/org", "token")

	require.NotNil(t, client)
	assert.Equal(t, DefaultTimeout, client.httpClient.Timeout)
	// Rate limiter should be initialized with TSTU defaults
	assert.Equal(t, 200, client.rateLimiter.Limit())
	assert.Equal(t, 200, client.rateLimiter.Remaining())
}

// TestClient_String tests String() method for safe logging (no token exposure)
func TestClient_String(t *testing.T) {
	client := NewClient("https://dev.azure.com/test-org", "super-secret-token-12345")

	str := client.String()

	// Should contain org URL
	assert.Contains(t, str, "https://dev.azure.com/test-org")
	// Should NOT contain actual token
	assert.NotContains(t, str, "super-secret-token-12345")
	// Should indicate token is redacted
	assert.Contains(t, str, "[REDACTED]")
}

// TestClient_GoString tests GoString() method for %#v format (no token exposure)
func TestClient_GoString(t *testing.T) {
	client := NewClient("https://dev.azure.com/test-org", "super-secret-token-12345")

	str := client.GoString()

	// Should contain org URL
	assert.Contains(t, str, "https://dev.azure.com/test-org")
	// Should NOT contain actual token
	assert.NotContains(t, str, "super-secret-token-12345")
	// Should indicate token is redacted
	assert.Contains(t, str, "[REDACTED]")
}

// TestClient_NilClient tests that nil client doesn't panic when formatted
func TestClient_NilClient(t *testing.T) {
	var client *Client

	// Should not panic
	assert.NotPanics(t, func() {
		_ = client.String()
		_ = client.GoString()
	})

	assert.Contains(t, client.String(), "nil")
	assert.Contains(t, client.GoString(), "nil")
}

// TestClient_PrepareRequest_JSONAcceptHeader tests that JSON requests use application/json Accept header
func TestClient_PrepareRequest_JSONAcceptHeader(t *testing.T) {
	client := NewClient("https://dev.azure.com/test-org", "test-token")

	req, err := client.prepareRequest(t.Context(), "GET", "/test")
	require.NoError(t, err)

	assert.Equal(t, "application/json", req.Header.Get("Accept"),
		"JSON requests should use application/json Accept header")
	assert.Contains(t, req.Header.Get("Authorization"), "Basic",
		"Authorization header should use Basic auth")
}
