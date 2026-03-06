// pkg/exploitation/shared/payloads/exfiltration_test.go
package payloads

import (
	"strings"
	"testing"
)

func TestExfiltrationPayloads_AllRegistered(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterExfiltrationPayloads(registry)

	expectedIDs := []string{
		// HTTP exfiltration
		"exfil-http-curl-token",
		"exfil-http-wget-encoded",
		"exfil-http-webhook",
		// DNS exfiltration
		"exfil-dns-subdomain",
		"exfil-dns-txt-record",
		// MCP-based (from arXiv:2506.23260)
		"exfil-mcp-toxic-flow",
		"exfil-mcp-capability-theft",
	}

	for _, id := range expectedIDs {
		if registry.Get(id) == nil {
			t.Errorf("missing expected payload: %s", id)
		}
	}
}

func TestExfiltrationPayloads_GitHubSpecific(t *testing.T) {
	registry := NewPayloadRegistry()
	RegisterExfiltrationPayloads(registry)

	payloads := registry.ListByPlatform("github")
	if len(payloads) == 0 {
		t.Error("no GitHub-specific exfiltration payloads found")
	}

	// Should include GITHUB_TOKEN references
	found := false
	for _, p := range payloads {
		if strings.Contains(p.Template, "GITHUB_TOKEN") ||
			strings.Contains(p.Template, "secrets.") {
			found = true
			break
		}
	}
	if !found {
		t.Error("GitHub payloads should reference GITHUB_TOKEN or secrets")
	}
}
