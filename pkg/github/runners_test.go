package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ListOrgRunners(t *testing.T) {
	tests := []struct {
		name         string
		org          string
		mockResponse string
		mockStatus   int
		wantRunners  int
		wantErr      bool
	}{
		{
			name: "successful enumeration",
			org:  "praetorian-inc",
			mockResponse: `{
                "total_count": 2,
                "runners": [
                    {"id": 23, "name": "runner-01", "os": "linux", "status": "online", "busy": false, "labels": []},
                    {"id": 24, "name": "runner-02", "os": "macos", "status": "offline", "busy": false, "labels": []}
                ]
            }`,
			mockStatus:  200,
			wantRunners: 2,
			wantErr:     false,
		},
		{
			name:         "empty runners list",
			org:          "no-runners-org",
			mockResponse: `{"total_count": 0, "runners": []}`,
			mockStatus:   200,
			wantRunners:  0,
			wantErr:      false,
		},
		{
			name:         "404 returns permission error",
			org:          "private-org",
			mockResponse: `{"message": "Not Found"}`,
			mockStatus:   404,
			wantRunners:  0,
			wantErr:      true,
		},
		{
			name:         "403 returns permission error",
			org:          "forbidden-org",
			mockResponse: `{"message": "Must have admin rights"}`,
			mockStatus:   403,
			wantRunners:  0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/orgs/" + tt.org + "/actions/runners"
				if r.URL.Path != expectedPath {
					t.Errorf("Path = %s, want %s", r.URL.Path, expectedPath)
				}

				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			runners, err := client.ListOrgRunners(context.Background(), tt.org)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListOrgRunners() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(runners) != tt.wantRunners {
				t.Errorf("ListOrgRunners() got %d runners, want %d", len(runners), tt.wantRunners)
			}
		})
	}
}

func TestClient_ListRepoRunners(t *testing.T) {
	tests := []struct {
		name         string
		owner        string
		repo         string
		mockResponse string
		mockStatus   int
		wantRunners  int
		wantErr      bool
	}{
		{
			name:  "successful enumeration",
			owner: "acme",
			repo:  "webapp",
			mockResponse: `{
                "total_count": 1,
                "runners": [
                    {"id": 100, "name": "repo-runner", "os": "linux", "status": "online", "busy": true, "labels": [{"id": 1, "name": "self-hosted"}]}
                ]
            }`,
			mockStatus:  200,
			wantRunners: 1,
			wantErr:     false,
		},
		{
			name:         "404 returns permission error",
			owner:        "private",
			repo:         "secret-repo",
			mockResponse: `{"message": "Not Found"}`,
			mockStatus:   404,
			wantRunners:  0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/repos/%s/%s/actions/runners", tt.owner, tt.repo)
				if r.URL.Path != expectedPath {
					t.Errorf("Path = %s, want %s", r.URL.Path, expectedPath)
				}

				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			runners, err := client.ListRepoRunners(context.Background(), tt.owner, tt.repo)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(runners) != tt.wantRunners {
				t.Errorf("got %d runners, want %d", len(runners), tt.wantRunners)
			}
		})
	}
}

func TestClient_ListOrgRunnerGroups(t *testing.T) {
	tests := []struct {
		name         string
		org          string
		mockResponse string
		mockStatus   int
		wantGroups   int
		wantErr      bool
	}{
		{
			name: "successful enumeration",
			org:  "praetorian-inc",
			mockResponse: `{
                "total_count": 2,
                "runner_groups": [
                    {"id": 1, "name": "Default", "visibility": "all", "default": true, "allows_public_repositories": true},
                    {"id": 2, "name": "Production", "visibility": "selected", "default": false, "allows_public_repositories": false}
                ]
            }`,
			mockStatus: 200,
			wantGroups: 2,
			wantErr:    false,
		},
		{
			name:         "404 returns permission error",
			org:          "private-org",
			mockResponse: `{"message": "Not Found"}`,
			mockStatus:   404,
			wantGroups:   0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/orgs/" + tt.org + "/actions/runner-groups"
				if r.URL.Path != expectedPath {
					t.Errorf("Path = %s, want %s", r.URL.Path, expectedPath)
				}

				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			groups, err := client.ListOrgRunnerGroups(context.Background(), tt.org)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(groups) != tt.wantGroups {
				t.Errorf("got %d groups, want %d", len(groups), tt.wantGroups)
			}
		})
	}
}
