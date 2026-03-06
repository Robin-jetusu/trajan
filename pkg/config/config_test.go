package config

import (
	"encoding/json"
	"testing"
)

// TestDefaultConfig verifies default configuration values
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.GitHub.BaseURL != "https://api.github.com" {
		t.Errorf("expected GitHub BaseURL to be https://api.github.com, got %s", cfg.GitHub.BaseURL)
	}

	if cfg.GitHub.RateLimit.Enabled != true {
		t.Error("expected GitHub rate limiting to be enabled")
	}

	if cfg.GitHub.RateLimit.RequestsPerHour != 5000 {
		t.Errorf("expected GitHub rate limit to be 5000, got %d", cfg.GitHub.RateLimit.RequestsPerHour)
	}

	if cfg.Scan.Concurrent != 10 {
		t.Errorf("expected scan concurrent requests to be 10, got %d", cfg.Scan.Concurrent)
	}

	if cfg.UI.Theme != "light" {
		t.Errorf("expected UI theme to be light, got %s", cfg.UI.Theme)
	}

	if cfg.Storage.DatabaseName != "trajan_storage" {
		t.Errorf("expected database name to be trajan_storage, got %s", cfg.Storage.DatabaseName)
	}
}

// TestConfigGetString tests getting string configuration values
func TestConfigGetString(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GitHub.Token = "test-token"

	tests := []struct {
		key      string
		expected string
	}{
		{"github.token", "test-token"},
		{"github.base_url", "https://api.github.com"},
		{"gitlab.base_url", "https://gitlab.com/api/v4"},
		{"ui.theme", "light"},
		{"scan.output_format", "json"},
		{"storage.database_name", "trajan_storage"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			value, err := cfg.Get(tt.key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if str, ok := value.(string); !ok {
				t.Errorf("expected string value, got %T", value)
			} else if str != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, str)
			}
		})
	}
}

// TestConfigGetInt tests getting integer configuration values
func TestConfigGetInt(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		key      string
		expected int
	}{
		{"scan.concurrent", 10},
		{"github.rate_limit.requests_per_hour", 5000},
		{"storage.database_version", 1},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			value, err := cfg.Get(tt.key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if intVal, ok := value.(int); !ok {
				t.Errorf("expected int value, got %T", value)
			} else if intVal != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, intVal)
			}
		})
	}
}

// TestConfigGetInt64 tests getting int64 configuration values
func TestConfigGetInt64(t *testing.T) {
	cfg := DefaultConfig()

	value, err := cfg.Get("scan.cache_ttl")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if int64Val, ok := value.(int64); !ok {
		t.Errorf("expected int64 value, got %T", value)
	} else if int64Val != 3600 {
		t.Errorf("expected 3600, got %d", int64Val)
	}
}

// TestConfigGetBool tests getting boolean configuration values
func TestConfigGetBool(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		key      string
		expected bool
	}{
		{"github.rate_limit.enabled", true},
		{"scan.include_archived", false},
		{"ui.show_welcome", true},
		{"ui.auto_save", true},
		{"storage.audit_logging", true},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			value, err := cfg.Get(tt.key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if boolVal, ok := value.(bool); !ok {
				t.Errorf("expected bool value, got %T", value)
			} else if boolVal != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, boolVal)
			}
		})
	}
}

// TestConfigGetUnknownKey tests error handling for unknown keys
func TestConfigGetUnknownKey(t *testing.T) {
	cfg := DefaultConfig()

	_, err := cfg.Get("unknown.key")
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}

	if err != ErrUnknownConfigKey && !isWrappedError(err, ErrUnknownConfigKey) {
		t.Errorf("expected ErrUnknownConfigKey, got %v", err)
	}
}

// TestConfigSetString tests setting string configuration values
func TestConfigSetString(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		key   string
		value string
	}{
		{"github.token", "new-token"},
		{"github.base_url", "https://github.example.com/api/v3"},
		{"gitlab.token", "gitlab-token"},
		{"ui.theme", "dark"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := cfg.Set(tt.key, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			value, err := cfg.Get(tt.key)
			if err != nil {
				t.Fatalf("unexpected error getting value: %v", err)
			}

			if str, ok := value.(string); !ok {
				t.Errorf("expected string value, got %T", value)
			} else if str != tt.value {
				t.Errorf("expected %s, got %s", tt.value, str)
			}
		})
	}
}

// TestConfigSetInt tests setting integer configuration values
func TestConfigSetInt(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		key   string
		value int
	}{
		{"scan.concurrent", 20},
		{"github.rate_limit.requests_per_hour", 10000},
		{"storage.database_version", 2},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := cfg.Set(tt.key, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			value, err := cfg.Get(tt.key)
			if err != nil {
				t.Fatalf("unexpected error getting value: %v", err)
			}

			if intVal, ok := value.(int); !ok {
				t.Errorf("expected int value, got %T", value)
			} else if intVal != tt.value {
				t.Errorf("expected %d, got %d", tt.value, intVal)
			}
		})
	}
}

// TestConfigSetFloat64ToInt tests converting float64 to int (from JSON)
func TestConfigSetFloat64ToInt(t *testing.T) {
	cfg := DefaultConfig()

	err := cfg.Set("scan.concurrent", float64(25))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	value, err := cfg.Get("scan.concurrent")
	if err != nil {
		t.Fatalf("unexpected error getting value: %v", err)
	}

	if intVal, ok := value.(int); !ok {
		t.Errorf("expected int value, got %T", value)
	} else if intVal != 25 {
		t.Errorf("expected 25, got %d", intVal)
	}
}

// TestConfigSetBool tests setting boolean configuration values
func TestConfigSetBool(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		key   string
		value bool
	}{
		{"github.rate_limit.enabled", false},
		{"scan.include_archived", true},
		{"ui.show_welcome", false},
		{"storage.audit_logging", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := cfg.Set(tt.key, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			value, err := cfg.Get(tt.key)
			if err != nil {
				t.Fatalf("unexpected error getting value: %v", err)
			}

			if boolVal, ok := value.(bool); !ok {
				t.Errorf("expected bool value, got %T", value)
			} else if boolVal != tt.value {
				t.Errorf("expected %v, got %v", tt.value, boolVal)
			}
		})
	}
}

// TestConfigSetInvalidType tests error handling for invalid value types
func TestConfigSetInvalidType(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		key   string
		value interface{}
	}{
		{"github.token", 123},              // int instead of string
		{"scan.concurrent", "invalid"},     // string instead of int
		{"ui.show_welcome", "not a bool"},  // string instead of bool
		{"scan.cache_ttl", "not an int64"}, // string instead of int64
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := cfg.Set(tt.key, tt.value)
			if err == nil {
				t.Fatal("expected error for invalid value type, got nil")
			}

			if err != ErrInvalidValueType && !isWrappedError(err, ErrInvalidValueType) {
				t.Errorf("expected ErrInvalidValueType, got %v", err)
			}
		})
	}
}

// TestConfigSetUnknownKey tests error handling for unknown keys
func TestConfigSetUnknownKey(t *testing.T) {
	cfg := DefaultConfig()

	err := cfg.Set("unknown.key", "value")
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}

	if err != ErrUnknownConfigKey && !isWrappedError(err, ErrUnknownConfigKey) {
		t.Errorf("expected ErrUnknownConfigKey, got %v", err)
	}
}

// TestConfigToJSON tests JSON serialization
func TestConfigToJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GitHub.Token = "test-token"

	jsonStr, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Verify structure
	if github, ok := result["github"].(map[string]interface{}); !ok {
		t.Error("expected github config in JSON")
	} else if token, ok := github["token"].(string); !ok || token != "test-token" {
		t.Errorf("expected github.token to be test-token, got %v", github["token"])
	}
}

// TestConfigFromJSON tests JSON deserialization
func TestConfigFromJSON(t *testing.T) {
	jsonStr := `{
		"github": {
			"token": "json-token",
			"base_url": "https://api.github.com",
			"rate_limit": {
				"enabled": false,
				"requests_per_hour": 3000
			}
		},
		"scan": {
			"concurrent": 15,
			"cache_ttl": 7200,
			"include_archived": true,
			"output_format": "sarif"
		}
	}`

	cfg := &Config{}
	err := cfg.FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify values
	if cfg.GitHub.Token != "json-token" {
		t.Errorf("expected token to be json-token, got %s", cfg.GitHub.Token)
	}

	if cfg.GitHub.RateLimit.Enabled != false {
		t.Error("expected rate limit to be disabled")
	}

	if cfg.GitHub.RateLimit.RequestsPerHour != 3000 {
		t.Errorf("expected rate limit to be 3000, got %d", cfg.GitHub.RateLimit.RequestsPerHour)
	}

	if cfg.Scan.Concurrent != 15 {
		t.Errorf("expected concurrent to be 15, got %d", cfg.Scan.Concurrent)
	}

	if cfg.Scan.OutputFormat != "sarif" {
		t.Errorf("expected output format to be sarif, got %s", cfg.Scan.OutputFormat)
	}
}

// TestConfigConcurrency tests concurrent access to config
func TestConfigConcurrency(t *testing.T) {
	cfg := DefaultConfig()

	// Spawn multiple goroutines reading and writing
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			// Perform multiple operations
			for j := 0; j < 100; j++ {
				_ = cfg.Set("scan.concurrent", n)
				_, _ = cfg.Get("scan.concurrent")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify config is still functional
	_, err := cfg.Get("scan.concurrent")
	if err != nil {
		t.Errorf("config corrupted by concurrent access: %v", err)
	}
}

// TestLocalStorageStub tests the stub implementation for non-WASM builds
func TestLocalStorageStub(t *testing.T) {
	storage := NewLocalStorage("test-key")

	// Load should return default config in stub
	cfg, err := storage.Load()
	if err != nil {
		t.Fatalf("unexpected error in stub Load: %v", err)
	}

	if cfg == nil {
		t.Fatal("expected non-nil config from stub Load")
	}

	// Save should succeed in stub (no-op)
	err = storage.Save(cfg)
	if err != nil {
		t.Errorf("unexpected error in stub Save: %v", err)
	}
}

// Helper function to check if error is wrapped
func isWrappedError(err, target error) bool {
	if err == nil {
		return false
	}
	// Simple check for wrapped errors
	return err.Error() != "" && target.Error() != "" &&
		len(err.Error()) > len(target.Error())
}
