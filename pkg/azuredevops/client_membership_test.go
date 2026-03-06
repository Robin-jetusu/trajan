package azuredevops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redirectTransport is a RoundTripper that redirects all requests to a fixed
// test server URL, regardless of the request's target host. This is needed
// because VSSPSClient() rewrites the base URL host to vssps.dev.azure.com,
// which would bypass a normal httptest.Server.
type redirectTransport struct {
	target *url.URL
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	redirected := req.Clone(req.Context())
	redirected.URL.Scheme = t.target.Scheme
	redirected.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(redirected)
}

func TestAddMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Contains(t, r.URL.Path, "/_apis/graph/memberships/")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"containerDescriptor":"group-desc","memberDescriptor":"user-desc"}`))
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	client := NewClient("https://dev.azure.com/testorg", "test-pat",
		WithHTTPClient(&http.Client{Transport: &redirectTransport{target: serverURL}}))

	err := client.AddMembership(context.Background(), "user-desc", "group-desc")
	require.NoError(t, err)
}

func TestRemoveMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Contains(t, r.URL.Path, "/_apis/graph/memberships/")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	client := NewClient("https://dev.azure.com/testorg", "test-pat",
		WithHTTPClient(&http.Client{Transport: &redirectTransport{target: serverURL}}))

	err := client.RemoveMembership(context.Background(), "user-desc", "group-desc")
	require.NoError(t, err)
}
