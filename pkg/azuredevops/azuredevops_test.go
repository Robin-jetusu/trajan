package azuredevops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPlatform wires a Platform to a test HTTP server.
func newTestPlatform(server *httptest.Server) *Platform {
	return &Platform{
		client: NewClient(server.URL, "test-pat"),
	}
}

// buildDefListJSON encodes a BuildDefinitionList with just id+name populated
// (mirroring the real ADO list endpoint which omits process/repository fields).
func buildDefListJSON(defs []BuildDefinition) string {
	list := BuildDefinitionList{Count: len(defs), Value: defs}
	b, _ := json.Marshal(list)
	return string(b)
}

// buildDefDetailJSON encodes a single BuildDefinition as the detail endpoint
// would return it (with process.yamlFilename populated).
func buildDefDetailJSON(def BuildDefinition) string {
	b, _ := json.Marshal(def)
	return string(b)
}

// makeShallowDef creates a summary-style BuildDefinition (id + name only,
// no process/repository fields) as returned by the list endpoint.
func makeShallowDef(id int, name string) BuildDefinition {
	var d BuildDefinition
	d.ID = id
	d.Name = name
	return d
}

// makeFullDef creates a detail-style BuildDefinition with process.yamlFilename
// populated, as returned by the GetBuildDefinition endpoint.
func makeFullDef(id int, name, yamlPath string) BuildDefinition {
	var d BuildDefinition
	d.ID = id
	d.Name = name
	d.Process.YamlFilename = yamlPath
	d.Process.Type = 2
	return d
}

// isListByRepo reports whether the request is a ListBuildDefinitionsByRepo call
// (has repositoryId query param).
func isListByRepo(r *http.Request) bool {
	return r.URL.Query().Get("repositoryId") != ""
}

// isGetDefinition reports whether the request is a GetBuildDefinition call
// (path matches /_apis/build/definitions/{id} with no extra query params
// beyond api-version).
func isGetDefinition(r *http.Request) (int, bool) {
	// Path looks like /MyProject/_apis/build/definitions/42
	parts := strings.Split(r.URL.Path, "/")
	// parts: ["", "MyProject", "_apis", "build", "definitions", "42"]
	if len(parts) < 6 {
		return 0, false
	}
	if parts[len(parts)-2] != "definitions" {
		return 0, false
	}
	// Must NOT have repositoryId (that would be the list-by-repo call)
	if r.URL.Query().Get("repositoryId") != "" {
		return 0, false
	}
	var id int
	_, err := fmt.Sscanf(parts[len(parts)-1], "%d", &id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// isGetWorkflowFile reports whether the request is a GetWorkflowFile call
// (path contains git/repositories).
func isGetWorkflowFile(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/git/repositories/")
}

// TestGetWorkflowsFromDefs_MultipleDefsForSameRepo verifies that two build
// definitions pointing to different YAML files both result in separate workflows.
func TestGetWorkflowsFromDefs_MultipleDefsForSameRepo(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	// Shallow defs returned by ListBuildDefinitionsByRepo.
	shallowDefs := []BuildDefinition{
		makeShallowDef(1, "CI"),
		makeShallowDef(2, "CD"),
	}
	// Full defs returned by GetBuildDefinition for each ID.
	fullDefs := map[int]BuildDefinition{
		1: makeFullDef(1, "CI", "ci.yml"),
		2: makeFullDef(2, "CD", "cd.yml"),
	}
	// File contents keyed by YAML path fragment.
	yamlContents := map[string]string{
		"ci.yml": "trigger:\n- main\n",
		"cd.yml": "trigger:\n- release\n",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(shallowDefs))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			for key, content := range yamlContents {
				if strings.Contains(rawPath, key) {
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprint(w, content)
					return
				}
			}
			http.Error(w, "not found: "+rawPath, http.StatusNotFound)

		default:
			if id, ok := isGetDefinition(r); ok {
				if def, found := fullDefs[id]; found {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, buildDefDetailJSON(def))
					return
				}
			}
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 2)

	paths := []string{workflows[0].Path, workflows[1].Path}
	assert.Contains(t, paths, "ci.yml")
	assert.Contains(t, paths, "cd.yml")

	for _, wf := range workflows {
		assert.Equal(t, projectName+"/"+repoName, wf.RepoSlug)
	}
}

// TestGetWorkflowsFromDefs_Deduplication verifies that two definitions both
// pointing to the same YAML file produce only one workflow and only one file fetch.
func TestGetWorkflowsFromDefs_Deduplication(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	shallowDefs := []BuildDefinition{
		makeShallowDef(1, "First"),
		makeShallowDef(2, "Second"),
	}
	fullDefs := map[int]BuildDefinition{
		// Both definitions point to the same YAML.
		1: makeFullDef(1, "First", "azure-pipelines.yml"),
		2: makeFullDef(2, "Second", "azure-pipelines.yml"),
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(shallowDefs))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			if strings.Contains(rawPath, "azure-pipelines.yml") {
				fetchCount++
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
				return
			}
			http.Error(w, "unexpected path: "+rawPath, http.StatusInternalServerError)

		default:
			if id, ok := isGetDefinition(r); ok {
				if def, found := fullDefs[id]; found {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, buildDefDetailJSON(def))
					return
				}
			}
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "duplicate YAML paths should produce only one workflow")
	assert.Equal(t, 1, fetchCount, "GetWorkflowFile should be called exactly once for deduplicated paths")
}

// TestGetWorkflowsFromDefs_FallbackOnListError verifies that a 500 from the
// ListBuildDefinitionsByRepo endpoint causes a fallback to azure-pipelines.yml.
func TestGetWorkflowsFromDefs_FallbackOnListError(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			// Simulate a server error on the list endpoint.
			http.Error(w, "internal server error", http.StatusInternalServerError)

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			if strings.Contains(rawPath, "azure-pipelines.yml") {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
				return
			}
			http.Error(w, "not found: "+rawPath, http.StatusNotFound)

		default:
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "fallback should return azure-pipelines.yml when list API fails")
	assert.Equal(t, "azure-pipelines.yml", workflows[0].Path)
	assert.Equal(t, projectName+"/"+repoName, workflows[0].RepoSlug)
}

// TestGetWorkflowsFromDefs_FallbackWhenNoDefs verifies that an empty definition
// list causes a fallback to azure-pipelines.yml.
func TestGetWorkflowsFromDefs_FallbackWhenNoDefs(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			// Return an empty list — no definitions registered for this repo.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(nil))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			if strings.Contains(rawPath, "azure-pipelines.yml") {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
				return
			}
			http.Error(w, "not found: "+rawPath, http.StatusNotFound)

		default:
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "fallback should return azure-pipelines.yml when no definitions exist")
	assert.Equal(t, "azure-pipelines.yml", workflows[0].Path)
	assert.Equal(t, projectName+"/"+repoName, workflows[0].RepoSlug)
}

// TestGetWorkflowsFromDefs_UnreadableYAMLSkipped verifies that a definition
// whose YAML file returns 404 is silently skipped while other valid definitions
// in the same list are still returned.
func TestGetWorkflowsFromDefs_UnreadableYAMLSkipped(t *testing.T) {
	const (
		projectName = "MyProject"
		repoName    = "my-repo"
		repoID      = "repo-guid-1234"
		branch      = "main"
	)

	shallowDefs := []BuildDefinition{
		makeShallowDef(1, "Missing CI"),
		makeShallowDef(2, "Valid CI"),
	}
	fullDefs := map[int]BuildDefinition{
		1: makeFullDef(1, "Missing CI", "missing.yml"),
		2: makeFullDef(2, "Valid CI", "valid.yml"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isListByRepo(r):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, buildDefListJSON(shallowDefs))

		case isGetWorkflowFile(r):
			rawPath := r.URL.Query().Get("path")
			switch {
			case strings.Contains(rawPath, "missing.yml"):
				http.Error(w, "not found", http.StatusNotFound)
			case strings.Contains(rawPath, "valid.yml"):
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "trigger:\n- main\n")
			default:
				http.Error(w, "unexpected path: "+rawPath, http.StatusInternalServerError)
			}

		default:
			if id, ok := isGetDefinition(r); ok {
				if def, found := fullDefs[id]; found {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, buildDefDetailJSON(def))
					return
				}
			}
			http.Error(w, "unexpected request: "+r.URL.String(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := newTestPlatform(server)
	workflows, err := p.getWorkflowsFromDefs(context.Background(), projectName, repoName, repoID, branch)

	require.NoError(t, err)
	require.Len(t, workflows, 1, "only the readable YAML should be returned")
	assert.Equal(t, "valid.yml", workflows[0].Path)
	assert.Equal(t, "Valid CI", workflows[0].Name)
}
