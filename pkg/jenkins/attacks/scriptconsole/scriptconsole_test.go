package scriptconsole

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if plugin.Name() != "script-console" {
		t.Errorf("Name() = %q, want %q", plugin.Name(), "script-console")
	}
	if plugin.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if plugin.Category() != attacks.CategoryCICD {
		t.Errorf("Category() = %q, want %q", plugin.Category(), attacks.CategoryCICD)
	}
}

func TestExecute_WithPayload_DryRun(t *testing.T) {
	serverCalled := false
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
		http.NotFound(w, r)
	}))

	plugin := New()
	result, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		Payload:   "println 'hello world'",
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.Success {
		t.Error("dry run should succeed")
	}
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("result.Data should be a map")
	}
	script, ok := data["script"].(string)
	if !ok {
		t.Fatal("result.Data[script] should be a string")
	}
	if script != "println 'hello world'" {
		t.Errorf("script = %q, want payload as-is", script)
	}
	if serverCalled {
		t.Error("dry run should not call the server")
	}
}

func TestExecute_WithCommand(t *testing.T) {
	var receivedScript string
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound)
		case "/scriptText":
			r.ParseForm()
			receivedScript = r.FormValue("script")
			w.Write([]byte("uid=0(root)"))
		default:
			http.NotFound(w, r)
		}
	}))

	plugin := New()
	result, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		DryRun:    false,
		ExtraOpts: map[string]string{
			"command": "whoami",
		},
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got message: %s", result.Message)
	}
	// Verify command was wrapped in Groovy
	if !strings.Contains(receivedScript, "'whoami'.execute()") {
		t.Errorf("expected Groovy-wrapped command, got: %q", receivedScript)
	}
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("result.Data should be a map")
	}
	output, ok := data["output"].(string)
	if !ok {
		t.Fatal("result.Data[output] should be a string")
	}
	if output != "uid=0(root)" {
		t.Errorf("output = %q, want %q", output, "uid=0(root)")
	}
}

func TestExecute_CommandEscaping(t *testing.T) {
	// Security-critical: verify that commands with single quotes and backslashes are properly escaped
	tests := []struct {
		name    string
		command string
		want    string // substring that must appear in the escaped script
	}{
		{
			name:    "single quotes",
			command: "echo 'hello world'",
			want:    `echo \'hello world\'`,
		},
		{
			name:    "backslashes",
			command: `echo hello\nworld`,
			want:    `echo hello\\nworld`,
		},
		{
			name:    "mixed special chars",
			command: `cat /etc/passwd | grep 'root'`,
			want:    `cat /etc/passwd | grep \'root\'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedScript string
			platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/crumbIssuer/api/json":
					w.WriteHeader(http.StatusNotFound)
				case "/scriptText":
					r.ParseForm()
					receivedScript = r.FormValue("script")
					w.Write([]byte("ok"))
				default:
					http.NotFound(w, r)
				}
			}))

			plugin := New()
			_, err := plugin.Execute(context.Background(), attacks.AttackOptions{
				SessionID: "test-session",
				Platform:  platform,
				DryRun:    false,
				ExtraOpts: map[string]string{
					"command": tt.command,
				},
			})
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !strings.Contains(receivedScript, tt.want) {
				t.Errorf("escaped script %q does not contain %q", receivedScript, tt.want)
			}
		})
	}
}

func TestExecute_NoPayloadNoCommand(t *testing.T) {
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))

	plugin := New()
	_, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		DryRun:    false,
	})
	if err == nil {
		t.Fatal("expected error when no payload and no command provided")
	}
	if !strings.Contains(err.Error(), "must provide") {
		t.Errorf("error message %q should mention 'must provide'", err.Error())
	}
}

func TestCleanup(t *testing.T) {
	plugin := New()
	err := plugin.Cleanup(context.Background(), &attacks.Session{})
	if err != nil {
		t.Errorf("Cleanup() returned error: %v", err)
	}
}
