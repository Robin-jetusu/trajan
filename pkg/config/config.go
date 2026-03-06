// Package config provides browser-compatible configuration management.
//
// This package uses localStorage for persistent configuration storage,
// replacing file-based configuration with browser storage via syscall/js.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrUnknownConfigKey is returned when an unknown configuration key is requested
	ErrUnknownConfigKey = errors.New("unknown configuration key")

	// ErrInvalidValueType is returned when a value of incorrect type is provided
	ErrInvalidValueType = errors.New("invalid value type for configuration key")
)

// Config represents the application configuration
type Config struct {
	// GitHub contains GitHub-specific configuration
	GitHub GitHubConfig `json:"github"`

	// GitLab contains GitLab-specific configuration
	GitLab GitLabConfig `json:"gitlab"`

	// Azure contains Azure DevOps-specific configuration
	Azure AzureConfig `json:"azure"`

	// Scan contains scan-specific configuration
	Scan ScanConfig `json:"scan"`

	// UI contains UI-specific configuration
	UI UIConfig `json:"ui"`

	// Storage contains storage-specific configuration
	Storage StorageConfig `json:"storage"`

	mu sync.RWMutex
}

// GitHubConfig contains GitHub configuration
type GitHubConfig struct {
	// Token is the GitHub authentication token
	Token string `json:"token"`

	// BaseURL is the GitHub API base URL (for GitHub Enterprise)
	BaseURL string `json:"base_url"`

	// RateLimit contains rate limiting configuration
	RateLimit RateLimitConfig `json:"rate_limit"`
}

// GitLabConfig contains GitLab configuration
type GitLabConfig struct {
	// Token is the GitLab authentication token
	Token string `json:"token"`

	// BaseURL is the GitLab API base URL
	BaseURL string `json:"base_url"`
}

// AzureConfig contains Azure DevOps configuration
type AzureConfig struct {
	// Token is the Azure DevOps PAT
	Token string `json:"token"`

	// Organization is the Azure DevOps organization
	Organization string `json:"organization"`
}

// ScanConfig contains scan configuration
type ScanConfig struct {
	// Concurrent is the default number of concurrent requests
	Concurrent int `json:"concurrent"`

	// CacheTTL is the cache TTL in seconds
	CacheTTL int64 `json:"cache_ttl"`

	// IncludeArchived includes archived repositories
	IncludeArchived bool `json:"include_archived"`

	// OutputFormat is the default output format
	OutputFormat string `json:"output_format"`
}

// UIConfig contains UI configuration
type UIConfig struct {
	// Theme is the UI theme ("light" or "dark")
	Theme string `json:"theme"`

	// ShowWelcome shows welcome screen on first load
	ShowWelcome bool `json:"show_welcome"`

	// AutoSave auto-saves configuration changes
	AutoSave bool `json:"auto_save"`
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	// DatabaseName is the IndexedDB database name
	DatabaseName string `json:"database_name"`

	// DatabaseVersion is the IndexedDB database version
	DatabaseVersion int `json:"database_version"`

	// AuditLogging enables audit logging
	AuditLogging bool `json:"audit_logging"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	// Enabled enables rate limiting
	Enabled bool `json:"enabled"`

	// RequestsPerHour is the maximum requests per hour
	RequestsPerHour int `json:"requests_per_hour"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		GitHub: GitHubConfig{
			BaseURL: "https://api.github.com",
			RateLimit: RateLimitConfig{
				Enabled:         true,
				RequestsPerHour: 5000,
			},
		},
		GitLab: GitLabConfig{
			BaseURL: "https://gitlab.com/api/v4",
		},
		Azure: AzureConfig{},
		Scan: ScanConfig{
			Concurrent:      10,
			CacheTTL:        3600, // 1 hour
			IncludeArchived: false,
			OutputFormat:    "json",
		},
		UI: UIConfig{
			Theme:       "light",
			ShowWelcome: true,
			AutoSave:    true,
		},
		Storage: StorageConfig{
			DatabaseName:    "trajan_storage",
			DatabaseVersion: 1,
			AuditLogging:    true,
		},
	}
}

// Get retrieves a configuration value by dot-notation key
func (c *Config) Get(key string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Parse dot-notation key
	switch key {
	// GitHub configuration
	case "github.token":
		return c.GitHub.Token, nil
	case "github.base_url":
		return c.GitHub.BaseURL, nil
	case "github.rate_limit.enabled":
		return c.GitHub.RateLimit.Enabled, nil
	case "github.rate_limit.requests_per_hour":
		return c.GitHub.RateLimit.RequestsPerHour, nil

	// GitLab configuration
	case "gitlab.token":
		return c.GitLab.Token, nil
	case "gitlab.base_url":
		return c.GitLab.BaseURL, nil

	// Azure configuration
	case "azure.token":
		return c.Azure.Token, nil
	case "azure.organization":
		return c.Azure.Organization, nil

	// Scan configuration
	case "scan.concurrent":
		return c.Scan.Concurrent, nil
	case "scan.cache_ttl":
		return c.Scan.CacheTTL, nil
	case "scan.include_archived":
		return c.Scan.IncludeArchived, nil
	case "scan.output_format":
		return c.Scan.OutputFormat, nil

	// UI configuration
	case "ui.theme":
		return c.UI.Theme, nil
	case "ui.show_welcome":
		return c.UI.ShowWelcome, nil
	case "ui.auto_save":
		return c.UI.AutoSave, nil

	// Storage configuration
	case "storage.database_name":
		return c.Storage.DatabaseName, nil
	case "storage.database_version":
		return c.Storage.DatabaseVersion, nil
	case "storage.audit_logging":
		return c.Storage.AuditLogging, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownConfigKey, key)
	}
}

// Set updates a configuration value by dot-notation key
func (c *Config) Set(key string, value interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Parse dot-notation key and perform type conversion
	switch key {
	// GitHub configuration
	case "github.token":
		if v, ok := value.(string); ok {
			c.GitHub.Token = v
			return nil
		}
		return fmt.Errorf("%w: expected string for github.token", ErrInvalidValueType)
	case "github.base_url":
		if v, ok := value.(string); ok {
			c.GitHub.BaseURL = v
			return nil
		}
		return fmt.Errorf("%w: expected string for github.base_url", ErrInvalidValueType)
	case "github.rate_limit.enabled":
		if v, ok := value.(bool); ok {
			c.GitHub.RateLimit.Enabled = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for github.rate_limit.enabled", ErrInvalidValueType)
	case "github.rate_limit.requests_per_hour":
		if v, ok := value.(int); ok {
			c.GitHub.RateLimit.RequestsPerHour = v
			return nil
		}
		// Handle float64 from JSON unmarshaling
		if v, ok := value.(float64); ok {
			c.GitHub.RateLimit.RequestsPerHour = int(v)
			return nil
		}
		return fmt.Errorf("%w: expected int for github.rate_limit.requests_per_hour", ErrInvalidValueType)

	// GitLab configuration
	case "gitlab.token":
		if v, ok := value.(string); ok {
			c.GitLab.Token = v
			return nil
		}
		return fmt.Errorf("%w: expected string for gitlab.token", ErrInvalidValueType)
	case "gitlab.base_url":
		if v, ok := value.(string); ok {
			c.GitLab.BaseURL = v
			return nil
		}
		return fmt.Errorf("%w: expected string for gitlab.base_url", ErrInvalidValueType)

	// Azure configuration
	case "azure.token":
		if v, ok := value.(string); ok {
			c.Azure.Token = v
			return nil
		}
		return fmt.Errorf("%w: expected string for azure.token", ErrInvalidValueType)
	case "azure.organization":
		if v, ok := value.(string); ok {
			c.Azure.Organization = v
			return nil
		}
		return fmt.Errorf("%w: expected string for azure.organization", ErrInvalidValueType)

	// Scan configuration
	case "scan.concurrent":
		if v, ok := value.(int); ok {
			c.Scan.Concurrent = v
			return nil
		}
		if v, ok := value.(float64); ok {
			c.Scan.Concurrent = int(v)
			return nil
		}
		return fmt.Errorf("%w: expected int for scan.concurrent", ErrInvalidValueType)
	case "scan.cache_ttl":
		if v, ok := value.(int64); ok {
			c.Scan.CacheTTL = v
			return nil
		}
		if v, ok := value.(float64); ok {
			c.Scan.CacheTTL = int64(v)
			return nil
		}
		return fmt.Errorf("%w: expected int64 for scan.cache_ttl", ErrInvalidValueType)
	case "scan.include_archived":
		if v, ok := value.(bool); ok {
			c.Scan.IncludeArchived = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for scan.include_archived", ErrInvalidValueType)
	case "scan.output_format":
		if v, ok := value.(string); ok {
			c.Scan.OutputFormat = v
			return nil
		}
		return fmt.Errorf("%w: expected string for scan.output_format", ErrInvalidValueType)

	// UI configuration
	case "ui.theme":
		if v, ok := value.(string); ok {
			c.UI.Theme = v
			return nil
		}
		return fmt.Errorf("%w: expected string for ui.theme", ErrInvalidValueType)
	case "ui.show_welcome":
		if v, ok := value.(bool); ok {
			c.UI.ShowWelcome = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for ui.show_welcome", ErrInvalidValueType)
	case "ui.auto_save":
		if v, ok := value.(bool); ok {
			c.UI.AutoSave = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for ui.auto_save", ErrInvalidValueType)

	// Storage configuration
	case "storage.database_name":
		if v, ok := value.(string); ok {
			c.Storage.DatabaseName = v
			return nil
		}
		return fmt.Errorf("%w: expected string for storage.database_name", ErrInvalidValueType)
	case "storage.database_version":
		if v, ok := value.(int); ok {
			c.Storage.DatabaseVersion = v
			return nil
		}
		if v, ok := value.(float64); ok {
			c.Storage.DatabaseVersion = int(v)
			return nil
		}
		return fmt.Errorf("%w: expected int for storage.database_version", ErrInvalidValueType)
	case "storage.audit_logging":
		if v, ok := value.(bool); ok {
			c.Storage.AuditLogging = v
			return nil
		}
		return fmt.Errorf("%w: expected bool for storage.audit_logging", ErrInvalidValueType)

	default:
		return fmt.Errorf("%w: %s", ErrUnknownConfigKey, key)
	}
}

// ToJSON serializes configuration to JSON
func (c *Config) ToJSON() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes configuration from JSON
func (c *Config) FromJSON(data string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return json.Unmarshal([]byte(data), c)
}

// Storage represents configuration storage interface
type Storage interface {
	// Load loads configuration from storage
	Load() (*Config, error)

	// Save saves configuration to storage
	Save(config *Config) error
}

// LocalStorage implements Storage using browser localStorage
type LocalStorage struct {
	key string
}

// NewLocalStorage creates a new localStorage adapter
func NewLocalStorage(key string) *LocalStorage {
	return &LocalStorage{
		key: key,
	}
}
