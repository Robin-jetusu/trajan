package azuredevops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_GetConnectionData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/connectionData")
		assert.Contains(t, r.URL.RawQuery, "api-version=7.1")

		resp := ConnectionData{}
		resp.AuthenticatedUser.ID = "user-123"
		resp.AuthenticatedUser.ProviderDisplayName = "Test User"
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	data, err := client.GetConnectionData(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "user-123", data.AuthenticatedUser.ID)
	assert.Equal(t, "Test User", data.AuthenticatedUser.ProviderDisplayName)
}

func TestClient_ListProjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/projects")

		resp := ProjectList{
			Value: []Project{
				{ID: "proj-1", Name: "Project1", Visibility: "private"},
				{ID: "proj-2", Name: "Project2", Visibility: "public"},
			},
			Count: 2,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	projects, err := client.ListProjects(context.Background())

	require.NoError(t, err)
	assert.Len(t, projects, 2)
	assert.Equal(t, "Project1", projects[0].Name)
}

func TestClient_ListPipelines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/pipelines")

		resp := PipelineList{
			Value: []Pipeline{
				{ID: 1, Name: "CI Pipeline"},
				{ID: 2, Name: "CD Pipeline"},
			},
			Count: 2,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	pipelines, err := client.ListPipelines(context.Background(), "TestProject")

	require.NoError(t, err)
	assert.Len(t, pipelines, 2)
}

func TestClient_ListAgentPools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/distributedtask/pools")

		resp := AgentPoolList{
			Value: []AgentPool{
				{ID: 1, Name: "Azure Pipelines", IsHosted: true},
				{ID: 2, Name: "Self-hosted", IsHosted: false},
			},
			Count: 2,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	pools, err := client.ListAgentPools(context.Background())

	require.NoError(t, err)
	assert.Len(t, pools, 2)
	assert.True(t, pools[0].IsHosted)
	assert.False(t, pools[1].IsHosted)
}

func TestClient_ListVariableGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/distributedtask/variablegroups")

		resp := VariableGroupList{
			Value: []VariableGroup{
				{
					ID:   1,
					Name: "Secrets",
					Variables: map[string]VariableValue{
						"API_KEY": {IsSecret: true},
						"ENV":     {Value: "prod", IsSecret: false},
					},
				},
			},
			Count: 1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	groups, err := client.ListVariableGroups(context.Background(), "TestProject")

	require.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.True(t, groups[0].Variables["API_KEY"].IsSecret)
}

func TestClient_ListServiceConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/serviceendpoint/endpoints")

		resp := ServiceConnectionList{
			Value: []ServiceConnection{
				{ID: "conn-1", Name: "Azure", Type: "azurerm"},
			},
			Count: 1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	conns, err := client.ListServiceConnections(context.Background(), "TestProject")

	require.NoError(t, err)
	assert.Len(t, conns, 1)
}

func TestClient_ListArtifactFeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/_apis/packaging/feeds")

		resp := ArtifactFeedList{
			Value: []ArtifactFeed{
				{ID: "feed-1", Name: "Artifacts"},
			},
			Count: 1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	feeds, err := client.ListArtifactFeeds(context.Background())

	require.NoError(t, err)
	assert.Len(t, feeds, 1)
}

func TestClient_GetVariableGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/_apis/distributedtask/variablegroups/")
		assert.Contains(t, r.URL.Path, "/1")
		assert.Contains(t, r.URL.RawQuery, "api-version=7.1")

		resp := VariableGroup{
			ID:   1,
			Name: "test-vg",
			Variables: map[string]VariableValue{
				"key1": {Value: "val1", IsSecret: false},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-pat")
	vg, err := client.GetVariableGroup(context.Background(), "MyProject", 1)

	require.NoError(t, err)
	assert.Equal(t, "test-vg", vg.Name)
	assert.Contains(t, vg.Variables, "key1")
}
