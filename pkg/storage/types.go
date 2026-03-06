package storage

import (
	"context"
	"time"
)

// Storage represents the browser storage interface
type Storage interface {
	// Initialize initializes the storage (creates databases/stores)
	Initialize(ctx context.Context) error

	// LogAudit stores an audit log entry
	LogAudit(ctx context.Context, entry *AuditEntry) error

	// SaveSession persists an attack session
	SaveSession(ctx context.Context, session *Session) error

	// LoadSession retrieves a session by ID
	LoadSession(ctx context.Context, id string) (*Session, error)

	// DeleteSession removes a session
	DeleteSession(ctx context.Context, id string) error

	// ListSessions retrieves all sessions
	ListSessions(ctx context.Context) ([]*Session, error)

	// SaveScanCache stores scan results in cache
	SaveScanCache(ctx context.Context, cache *ScanCache) error

	// LoadScanCache retrieves cached scan results
	LoadScanCache(ctx context.Context, key string) (*ScanCache, error)

	// Close closes the storage connection
	Close() error
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	// Timestamp is the entry timestamp
	Timestamp time.Time `json:"timestamp"`

	// SessionID is the associated session identifier
	SessionID string `json:"sessionID"`

	// Plugin is the attack plugin name
	Plugin string `json:"plugin"`

	// Action is the action performed
	Action string `json:"action"`

	// Target is the target repository
	Target string `json:"target"`

	// Result contains action-specific results
	Result map[string]interface{} `json:"result"`

	// Metadata contains additional metadata
	Metadata map[string]interface{} `json:"metadata"`
}

// Session represents an attack session
type Session struct {
	// ID is the unique session identifier
	ID string `json:"id"`

	// Plugin is the plugin name
	Plugin string `json:"plugin"`

	// Target is the target repository
	Target string `json:"target"`

	// Artifacts are created artifacts
	Artifacts []Artifact `json:"artifacts"`

	// CleanupActions are pending cleanup actions
	CleanupActions []CleanupAction `json:"cleanupActions"`

	// CreatedAt is the creation timestamp
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt is the last update timestamp
	UpdatedAt time.Time `json:"updatedAt"`

	// Status is the session status
	Status string `json:"status"`

	// Metadata contains additional metadata
	Metadata map[string]interface{} `json:"metadata"`
}

// Artifact represents a created artifact
type Artifact struct {
	// Type is the artifact type
	Type string `json:"type"`

	// ID is the unique identifier
	ID string `json:"id"`

	// URL is the full URL
	URL string `json:"url"`

	// CreatedAt is the creation timestamp
	CreatedAt time.Time `json:"createdAt"`

	// Metadata contains additional information
	Metadata map[string]interface{} `json:"metadata"`
}

// CleanupAction represents a deferred cleanup action
type CleanupAction struct {
	// Type is the cleanup action type
	Type string `json:"type"`

	// Params contains action parameters
	Params map[string]interface{} `json:"params"`
}

// ScanCache represents cached scan results
type ScanCache struct {
	// Key is the cache key (typically hash of repo URL)
	Key string `json:"key"`

	// URL is the repository URL
	URL string `json:"url"`

	// Results are the scan findings
	Results interface{} `json:"results"`

	// CachedAt is the cache timestamp
	CachedAt time.Time `json:"cached_at"`

	// TTL is the time-to-live in seconds
	TTL int64 `json:"ttl"`

	// ExpiresAt is the expiration timestamp
	ExpiresAt time.Time `json:"expires_at"`
}
