package credentialdump

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/jenkins"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func newTestPlatform(t *testing.T, handler http.Handler) *jenkins.Platform {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p := jenkins.NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		BaseURL: srv.URL,
		Token:   "test-token",
		Jenkins: &platforms.JenkinsAuth{Username: "admin"},
	})
	if err != nil {
		t.Fatalf("failed to init platform: %v", err)
	}
	return p
}

func TestNew(t *testing.T) {
	plugin := New()
	if plugin.Name() != "credential-dump" {
		t.Errorf("Name() = %q, want %q", plugin.Name(), "credential-dump")
	}
	if plugin.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if plugin.Category() != attacks.CategorySecrets {
		t.Errorf("Category() = %q, want %q", plugin.Category(), attacks.CategorySecrets)
	}
}

func TestCanAttack_WithScriptFinding(t *testing.T) {
	plugin := New()
	// CanAttack always returns true for credential-dump (also applicable if forced)
	got := plugin.CanAttack(nil)
	if !got {
		t.Error("CanAttack(nil) = false, want true")
	}
}

func TestExecute_DryRun(t *testing.T) {
	serverCalled := false
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		http.NotFound(w, r)
	}))

	plugin := New()
	result, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.Success {
		t.Error("dry run should succeed")
	}
	if result.Message == "" {
		t.Error("dry run should have a message")
	}
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("result.Data should be a map")
	}
	if _, ok := data["script"]; !ok {
		t.Error("dry run data should include 'script'")
	}
	if serverCalled {
		t.Error("dry run should not call the server")
	}
}

func TestExecute_Success(t *testing.T) {
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound) // CSRF disabled
		case "/scriptText":
			w.Write([]byte("ID: my-secret\nDescription: test\nType: UsernamePasswordCredentials\nUsername: admin\nPassword: s3cret\n---\n"))
		default:
			http.NotFound(w, r)
		}
	}))

	plugin := New()
	result, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		DryRun:    false,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got message: %s", result.Message)
	}
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("result.Data should be a map")
	}
	output, ok := data["output"].(string)
	if !ok {
		t.Fatal("result.Data[output] should be a string")
	}
	if output == "" {
		t.Error("expected non-empty output")
	}
}

func TestExecute_ScriptFailure(t *testing.T) {
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound)
		case "/scriptText":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access denied"))
		default:
			http.NotFound(w, r)
		}
	}))

	plugin := New()
	result, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		DryRun:    false,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	// The plugin sets Success=false but does not return an error on script failure
	if result.Success {
		t.Error("expected Success=false when script execution fails")
	}
}

func TestCleanup(t *testing.T) {
	plugin := New()
	err := plugin.Cleanup(context.Background(), &attacks.Session{})
	if err != nil {
		t.Errorf("Cleanup() returned error: %v", err)
	}
}
