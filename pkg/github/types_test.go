package github

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestSecret_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    Secret
		wantErr bool
	}{
		{
			name: "valid secret",
			json: `{
                "name": "AWS_ACCESS_KEY_ID",
                "created_at": "2025-01-15T14:20:27Z",
                "updated_at": "2025-12-20T10:00:00Z",
                "visibility": "selected"
            }`,
			want: Secret{
				Name:       "AWS_ACCESS_KEY_ID",
				CreatedAt:  time.Date(2025, 1, 15, 14, 20, 27, 0, time.UTC),
				UpdatedAt:  time.Date(2025, 12, 20, 10, 0, 0, 0, time.UTC),
				Visibility: "selected",
			},
			wantErr: false,
		},
		{
			name: "secret without visibility",
			json: `{
                "name": "DATABASE_URL",
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z"
            }`,
			want: Secret{
				Name:       "DATABASE_URL",
				CreatedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				UpdatedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				Visibility: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Secret
			err := json.Unmarshal([]byte(tt.json), &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Name != tt.want.Name {
				t.Errorf("Name = %v, want %v", got.Name, tt.want.Name)
			}
			if got.Visibility != tt.want.Visibility {
				t.Errorf("Visibility = %v, want %v", got.Visibility, tt.want.Visibility)
			}
		})
	}
}

func TestSecretsResponse_UnmarshalJSON(t *testing.T) {
	jsonData := `{
        "total_count": 2,
        "secrets": [
            {"name": "SECRET_A", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"},
            {"name": "SECRET_B", "created_at": "2025-01-02T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z"}
        ]
    }`

	var resp SecretsResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if resp.TotalCount != 2 {
		t.Errorf("TotalCount = %d, want 2", resp.TotalCount)
	}
	if len(resp.Secrets) != 2 {
		t.Errorf("len(Secrets) = %d, want 2", len(resp.Secrets))
	}
}

func TestAPIError_Error(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "Not Found",
		Resource:   "secrets",
		Scope:      "org",
		Target:     "acme-corp",
	}

	expected := "GitHub API error 404 for org acme-corp (secrets): Not Found"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestIsPermissionDenied(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "404 is permission denied",
			err:  &APIError{StatusCode: 404, Message: "Not Found"},
			want: true,
		},
		{
			name: "403 is permission denied",
			err:  &APIError{StatusCode: 403, Message: "Forbidden"},
			want: true,
		},
		{
			name: "500 is not permission denied",
			err:  &APIError{StatusCode: 500, Message: "Server Error"},
			want: false,
		},
		{
			name: "non-APIError is not permission denied",
			err:  fmt.Errorf("some error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermissionDenied(tt.err); got != tt.want {
				t.Errorf("IsPermissionDenied() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunner_UnmarshalJSON(t *testing.T) {
	jsonStr := `{
        "id": 23,
        "name": "runner-01",
        "os": "linux",
        "status": "online",
        "busy": false,
        "labels": [
            {"id": 5, "name": "self-hosted"},
            {"id": 7, "name": "X64"},
            {"id": 11, "name": "linux"}
        ]
    }`

	var runner Runner
	if err := json.Unmarshal([]byte(jsonStr), &runner); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if runner.ID != 23 {
		t.Errorf("ID = %d, want 23", runner.ID)
	}
	if runner.Name != "runner-01" {
		t.Errorf("Name = %s, want runner-01", runner.Name)
	}
	if runner.OS != "linux" {
		t.Errorf("OS = %s, want linux", runner.OS)
	}
	if runner.Status != "online" {
		t.Errorf("Status = %s, want online", runner.Status)
	}
	if runner.Busy != false {
		t.Errorf("Busy = %v, want false", runner.Busy)
	}
	if len(runner.Labels) != 3 {
		t.Errorf("len(Labels) = %d, want 3", len(runner.Labels))
	}
}

func TestRunnerGroup_UnmarshalJSON(t *testing.T) {
	jsonStr := `{
        "id": 2,
        "name": "Production",
        "visibility": "selected",
        "default": false,
        "allows_public_repositories": false,
        "restricted_to_workflows": true,
        "selected_workflows": ["deploy.yml", "release.yml"]
    }`

	var group RunnerGroup
	if err := json.Unmarshal([]byte(jsonStr), &group); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if group.ID != 2 {
		t.Errorf("ID = %d, want 2", group.ID)
	}
	if group.Name != "Production" {
		t.Errorf("Name = %s, want Production", group.Name)
	}
	if group.AllowsPublicRepositories != false {
		t.Errorf("AllowsPublicRepositories = %v, want false", group.AllowsPublicRepositories)
	}
	if len(group.SelectedWorkflows) != 2 {
		t.Errorf("len(SelectedWorkflows) = %d, want 2", len(group.SelectedWorkflows))
	}
}

func TestTokenInfoResultFields(t *testing.T) {
	result := &TokenInfoResult{
		TokenInfo:        nil,
		PermissionErrors: []string{},
		Errors:           []error{},
	}

	// Verify fields exist - compile time check
	if result.PermissionErrors == nil {
		result.PermissionErrors = []string{}
	}
	if result.Errors == nil {
		result.Errors = []error{}
	}
}
