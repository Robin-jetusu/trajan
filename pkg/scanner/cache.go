package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

// ScanResultCache caches scan results to avoid re-scanning identical workflow content
type ScanResultCache struct {
	entries map[string]*ScanCacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	hits    int64
	misses  int64
}

// ScanCacheEntry stores cached scan results with metadata
type ScanCacheEntry struct {
	Findings    []detections.Finding
	CachedAt    time.Time
	ExpiresAt   time.Time
	ContentHash string
}

// Get retrieves cached scan results if available and not expired
// Returns findings and true if hit, nil and false if miss
func (c *ScanResultCache) Get(repoSlug, workflowPath, content string) ([]detections.Finding, bool) {
	key := contentHash(repoSlug, workflowPath, content)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	atomic.AddInt64(&c.hits, 1)
	return entry.Findings, true
}

// Set stores scan results in the cache
func (c *ScanResultCache) Set(repoSlug, workflowPath, content string, findings []detections.Finding) {
	key := contentHash(repoSlug, workflowPath, content)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &ScanCacheEntry{
		Findings:    findings,
		CachedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(c.ttl),
		ContentHash: key,
	}

	c.entries[key] = entry
}

// contentHash generates a deterministic hash from repo, path, and content
func contentHash(repoSlug, workflowPath, content string) string {
	h := sha256.New()
	h.Write([]byte(repoSlug + ":" + workflowPath + ":" + content))
	return hex.EncodeToString(h.Sum(nil))
}
