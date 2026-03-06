package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseScopes(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected []string
	}{
		{
			name:     "empty header",
			header:   "",
			expected: []string{},
		},
		{
			name:     "single scope",
			header:   "repo",
			expected: []string{"repo"},
		},
		{
			name:     "multiple scopes",
			header:   "repo, workflow, read:org",
			expected: []string{"repo", "workflow", "read:org"},
		},
		{
			name:     "scopes with extra whitespace",
			header:   "  repo ,  workflow  , read:org  ",
			expected: []string{"repo", "workflow", "read:org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseScopes(tt.header)
			if len(result) != len(tt.expected) {
				t.Errorf("parseScopes() len = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, s := range result {
				if s != tt.expected[i] {
					t.Errorf("parseScopes()[%d] = %q, want %q", i, s, tt.expected[i])
				}
			}
		})
	}
}

func TestParseExpiration(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantNil  bool
		wantYear int // simplified check
	}{
		{
			name:    "empty header",
			header:  "",
			wantNil: true,
		},
		{
			name:     "valid expiration",
			header:   "2024-01-15 09:30:00 UTC",
			wantNil:  false,
			wantYear: 2024,
		},
		{
			name:    "invalid format",
			header:  "not-a-date",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExpiration(tt.header)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseExpiration() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Error("parseExpiration() = nil, want non-nil")
				return
			}
			if result.Year() != tt.wantYear {
				t.Errorf("parseExpiration().Year() = %d, want %d", result.Year(), tt.wantYear)
			}
		})
	}
}

func TestDetectTokenType(t *testing.T) {
	tests := []struct {
		name          string
		scopes        []string
		hasExpiration bool
		token         string
		expected      TokenType
	}{
		{
			name:          "classic PAT with scopes",
			scopes:        []string{"repo", "workflow"},
			hasExpiration: false,
			token:         "ghp_test123",
			expected:      TokenTypeClassic,
		},
		{
			name:          "classic PAT with scopes and expiration",
			scopes:        []string{"repo"},
			hasExpiration: true,
			token:         "ghp_test456",
			expected:      TokenTypeClassic,
		},
		{
			name:          "fine-grained PAT (no scopes, has expiration)",
			scopes:        []string{},
			hasExpiration: true,
			token:         "github_pat_test789",
			expected:      TokenTypeFineGrained,
		},
		{
			name:          "unknown (no scopes, no expiration)",
			scopes:        []string{},
			hasExpiration: false,
			token:         "unknown_token",
			expected:      TokenTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectTokenType(tt.scopes, tt.hasExpiration, tt.token)
			if result != tt.expected {
				t.Errorf("detectTokenType() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestClient_GetTokenInfo(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		oauthScopes    string
		tokenExpiry    string
		wantErr        bool
		wantUser       string
		wantType       TokenType
		wantScopeCount int
	}{
		{
			name:           "classic PAT",
			statusCode:     http.StatusOK,
			responseBody:   `{"login": "testuser", "name": "Test User"}`,
			oauthScopes:    "repo, workflow",
			tokenExpiry:    "",
			wantErr:        false,
			wantUser:       "testuser",
			wantType:       TokenTypeClassic,
			wantScopeCount: 2,
		},
		{
			name:           "fine-grained PAT",
			statusCode:     http.StatusOK,
			responseBody:   `{"login": "fguser", "name": "FG User"}`,
			oauthScopes:    "",
			tokenExpiry:    "2024-12-31 23:59:59 UTC",
			wantErr:        false,
			wantUser:       "fguser",
			wantType:       TokenTypeFineGrained,
			wantScopeCount: 0,
		},
		{
			name:         "invalid token",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"message": "Bad credentials"}`,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/user" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if tt.oauthScopes != "" {
					w.Header().Set("X-OAuth-Scopes", tt.oauthScopes)
				}
				if tt.tokenExpiry != "" {
					w.Header().Set("Github-Authentication-Token-Expiration", tt.tokenExpiry)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			info, err := client.GetTokenInfo(context.Background())

			if tt.wantErr {
				if err == nil {
					t.Error("GetTokenInfo() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GetTokenInfo() unexpected error: %v", err)
				return
			}

			if info.User != tt.wantUser {
				t.Errorf("GetTokenInfo().User = %q, want %q", info.User, tt.wantUser)
			}
			if info.Type != tt.wantType {
				t.Errorf("GetTokenInfo().Type = %q, want %q", info.Type, tt.wantType)
			}
			if len(info.Scopes) != tt.wantScopeCount {
				t.Errorf("GetTokenInfo().Scopes len = %d, want %d", len(info.Scopes), tt.wantScopeCount)
			}
		})
	}
}
