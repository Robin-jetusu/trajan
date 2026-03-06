// pkg/platforms/azuredevops/ratelimit.go
package azuredevops

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiter tracks Azure DevOps API rate limits using TSTU (Time-Shared Throughput Units) model
// Azure DevOps rate limit: 200 TSTUs per 5-minute sliding window per user/pipeline
// Reference: https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits
type RateLimiter struct {
	remaining int       // TSTUs remaining in current window
	limit     int       // Total TSTU quota (200)
	reset     time.Time // When the 5-minute window resets
	mu        sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with Azure DevOps TSTU defaults
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		remaining: 200, // Azure DevOps default: 200 TSTUs
		limit:     200,
		reset:     time.Now().Add(5 * time.Minute), // 5-minute sliding window
	}
}

// Update updates the rate limiter from HTTP response headers
// Azure DevOps uses X-RateLimit-* headers (similar to BitBucket, GitHub)
// Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
func (r *RateLimiter) Update(header http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Azure DevOps headers use X-RateLimit-* prefix
	if remaining := header.Get("X-RateLimit-Remaining"); remaining != "" {
		r.remaining, _ = strconv.Atoi(remaining)
	}
	if limit := header.Get("X-RateLimit-Limit"); limit != "" {
		r.limit, _ = strconv.Atoi(limit)
	}
	if reset := header.Get("X-RateLimit-Reset"); reset != "" {
		unix, _ := strconv.ParseInt(reset, 10, 64)
		r.reset = time.Unix(unix, 0)
	}
}

// ShouldThrottle returns true if we should proactively slow down
// Triggers at 10% remaining TSTUs to avoid hitting hard limit
// For 200 TSTU limit, throttles when <20 TSTUs remain
func (r *RateLimiter) ShouldThrottle() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.limit == 0 {
		return false // No rate limit information available
	}
	threshold := r.limit / 10 // 10% threshold
	return r.remaining < threshold
}

// Wait blocks until it's safe to make another request
// Returns immediately if not throttling, otherwise waits until reset time
func (r *RateLimiter) Wait(ctx context.Context) error {
	if !r.ShouldThrottle() {
		return nil
	}

	r.mu.RLock()
	waitDuration := time.Until(r.reset) + time.Second // Add 1s buffer
	r.mu.RUnlock()

	if waitDuration <= 0 {
		return nil // Reset time is in the past
	}

	select {
	case <-time.After(waitDuration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Remaining returns the current remaining TSTUs
func (r *RateLimiter) Remaining() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.remaining
}

// Limit returns the TSTU rate limit
func (r *RateLimiter) Limit() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.limit
}

// ResetTime returns when the 5-minute TSTU window resets
func (r *RateLimiter) ResetTime() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reset
}
