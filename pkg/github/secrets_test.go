package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_ListOrgActionsSecrets(t *testing.T) {
	tests := []struct {
		name         string
		org          string
		mockResponse string
		mockStatus   int
		wantSecrets  int
		wantErr      bool
	}{
		{
			name: "successful enumeration",
			org:  "praetorian-inc",
			mockResponse: `{
                "total_count": 2,
                "secrets": [
                    {"name": "AWS_KEY", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"},
                    {"name": "DB_URL", "created_at": "2025-01-02T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z"}
                ]
            }`,
			mockStatus:  200,
			wantSecrets: 2,
			wantErr:     false,
		},
		{
			name:         "empty secrets list",
			org:          "empty-org",
			mockResponse: `{"total_count": 0, "secrets": []}`,
			mockStatus:   200,
			wantSecrets:  0,
			wantErr:      false,
		},
		{
			name:         "404 returns empty (not error)",
			org:          "private-org",
			mockResponse: `{"message": "Not Found"}`,
			mockStatus:   404,
			wantSecrets:  0,
			wantErr:      false, // 404 treated as no access, not error
		},
		{
			name:         "403 forbidden returns empty (not error)",
			org:          "forbidden-org",
			mockResponse: `{"message": "Must have admin rights"}`,
			mockStatus:   403,
			wantSecrets:  0,
			wantErr:      false, // 403 treated as no access, not error
		},
		{
			name:         "500 server error returns error",
			org:          "broken-org",
			mockResponse: `{"message": "Internal Server Error"}`,
			mockStatus:   500,
			wantSecrets:  0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request path
				expectedPath := "/orgs/" + tt.org + "/actions/secrets"
				if r.URL.Path != expectedPath {
					t.Errorf("Path = %s, want %s", r.URL.Path, expectedPath)
				}

				// Verify auth header
				if auth := r.Header.Get("Authorization"); auth == "" {
					t.Error("Missing Authorization header")
				}

				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			secrets, err := client.ListOrgActionsSecrets(context.Background(), tt.org)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListOrgActionsSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(secrets) != tt.wantSecrets {
				t.Errorf("ListOrgActionsSecrets() got %d secrets, want %d", len(secrets), tt.wantSecrets)
			}
		})
	}
}

func TestClient_ListRepoActionsSecrets(t *testing.T) {
	tests := []struct {
		name         string
		owner        string
		repo         string
		mockResponse string
		mockStatus   int
		wantSecrets  int
		wantErr      bool
	}{
		{
			name:  "successful enumeration",
			owner: "acme",
			repo:  "webapp",
			mockResponse: `{
                "total_count": 3,
                "secrets": [
                    {"name": "API_KEY", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"},
                    {"name": "DB_URL", "created_at": "2025-01-02T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z"},
                    {"name": "TOKEN", "created_at": "2025-01-03T00:00:00Z", "updated_at": "2025-01-03T00:00:00Z"}
                ]
            }`,
			mockStatus:  200,
			wantSecrets: 3,
			wantErr:     false,
		},
		{
			name:         "404 returns empty",
			owner:        "private",
			repo:         "secret-repo",
			mockResponse: `{"message": "Not Found"}`,
			mockStatus:   404,
			wantSecrets:  0,
			wantErr:      false,
		},
		{
			name:         "403 forbidden returns empty",
			owner:        "forbidden",
			repo:         "forbidden-repo",
			mockResponse: `{"message": "Forbidden"}`,
			mockStatus:   403,
			wantSecrets:  0,
			wantErr:      false,
		},
		{
			name:         "500 server error returns error",
			owner:        "broken",
			repo:         "broken-repo",
			mockResponse: `{"message": "Internal Server Error"}`,
			mockStatus:   500,
			wantSecrets:  0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/repos/%s/%s/actions/secrets", tt.owner, tt.repo)
				if r.URL.Path != expectedPath {
					t.Errorf("Path = %s, want %s", r.URL.Path, expectedPath)
				}

				// Verify auth header
				if auth := r.Header.Get("Authorization"); auth == "" {
					t.Error("Missing Authorization header")
				}

				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockResponse))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			secrets, err := client.ListRepoActionsSecrets(context.Background(), tt.owner, tt.repo)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(secrets) != tt.wantSecrets {
				t.Errorf("got %d secrets, want %d", len(secrets), tt.wantSecrets)
			}
		})
	}
}
