// pkg/platforms/shared/ratelimit/ratelimit.go
package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Config defines platform-specific rate limit configuration
type Config struct {
	// HeaderPrefix is the HTTP header prefix for rate limit headers
	// Examples: "X-RateLimit-" (GitHub, Bitbucket), "RateLimit-" (GitLab)
	HeaderPrefix string

	// DefaultLimit is the initial rate limit value
	// Examples: 5000 (GitHub), 2000 (GitLab), 1000 (Bitbucket)
	DefaultLimit int

	// DefaultRemaining is the initial remaining requests count
	// Typically same as DefaultLimit
	DefaultRemaining int

	// ThresholdPercent is the percentage below which to trigger throttling
	// Examples: 5 (GitHub), 10 (GitLab, Bitbucket)
	ThresholdPercent int

	// ResetDuration is the default duration until rate limit resets
	// Examples: 1 hour (GitHub, Bitbucket), 1 minute (GitLab)
	ResetDuration time.Duration

	// SupportsRetryAfter indicates if platform supports Retry-After header
	// true for GitHub (secondary rate limits), false for GitLab/Bitbucket
	SupportsRetryAfter bool
}

// Limiter tracks API rate limits and throttles requests when needed
type Limiter struct {
	config     Config
	remaining  int
	limit      int
	reset      time.Time
	retryAfter time.Time // Secondary rate limit (optional, GitHub only)
	mu         sync.RWMutex
}

// New creates a new rate limiter with the given configuration
func New(config Config) *Limiter {
	return &Limiter{
		config:    config,
		remaining: config.DefaultRemaining,
		limit:     config.DefaultLimit,
		reset:     time.Now().Add(config.ResetDuration),
	}
}

// Update updates the rate limiter from HTTP response headers
// Uses the configured HeaderPrefix to read the correct headers
func (l *Limiter) Update(header http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Read rate limit headers using configured prefix
	remainingHeader := l.config.HeaderPrefix + "Remaining"
	limitHeader := l.config.HeaderPrefix + "Limit"
	resetHeader := l.config.HeaderPrefix + "Reset"

	if remaining := header.Get(remainingHeader); remaining != "" {
		l.remaining, _ = strconv.Atoi(remaining)
	}
	if limit := header.Get(limitHeader); limit != "" {
		l.limit, _ = strconv.Atoi(limit)
	}
	if reset := header.Get(resetHeader); reset != "" {
		unix, _ := strconv.ParseInt(reset, 10, 64)
		l.reset = time.Unix(unix, 0)
	}

	// Handle Retry-After header if supported (GitHub secondary rate limits)
	if l.config.SupportsRetryAfter {
		if retryAfter := header.Get("Retry-After"); retryAfter != "" {
			seconds, _ := strconv.Atoi(retryAfter)
			l.retryAfter = time.Now().Add(time.Duration(seconds) * time.Second)
		}
	}
}

// ShouldThrottle returns true if we should proactively slow down
// Uses the configured ThresholdPercent to determine when to throttle
func (l *Limiter) ShouldThrottle() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.limit == 0 {
		return false
	}

	// Calculate threshold based on configured percentage
	// Examples: limit*5/100 = 5%, limit*10/100 = 10%
	threshold := l.limit * l.config.ThresholdPercent / 100
	return l.remaining < threshold
}

// Wait blocks until it's safe to make another request
// Priority order (per GitHub docs, applies to all platforms):
// 1. Retry-After header (secondary rate limits, GitHub only)
// 2. Primary rate limit threshold
// 3. Return immediately if above threshold
func (l *Limiter) Wait(ctx context.Context) error {
	// Priority 1: Check retry-after (secondary limits, GitHub only)
	if l.config.SupportsRetryAfter {
		l.mu.RLock()
		retryAfter := l.retryAfter
		l.mu.RUnlock()

		if !retryAfter.IsZero() && time.Now().Before(retryAfter) {
			waitDuration := time.Until(retryAfter)

			select {
			case <-time.After(waitDuration):
				// Clear retryAfter after waiting
				l.mu.Lock()
				l.retryAfter = time.Time{}
				l.mu.Unlock()
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// Priority 2: Check primary rate limit (proactive throttle at threshold)
	if !l.ShouldThrottle() {
		return nil
	}

	l.mu.RLock()
	remaining := l.remaining
	limit := l.limit
	waitDuration := time.Until(l.reset) + time.Second
	l.mu.RUnlock()

	if waitDuration <= 0 {
		return nil
	}

	// Always show pausing message (user needs to know why scan is slow)
	fmt.Fprintf(os.Stderr, "Rate limit approaching (%d/%d remaining), pausing for %v...\n", remaining, limit, waitDuration)

	select {
	case <-time.After(waitDuration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Remaining returns the current remaining requests
func (l *Limiter) Remaining() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.remaining
}

// Limit returns the rate limit
func (l *Limiter) Limit() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.limit
}

// ResetTime returns when the rate limit resets
func (l *Limiter) ResetTime() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.reset
}

// RetryAfter returns when we can retry after secondary limit (GitHub only)
// Returns zero time if not supported or not set
func (l *Limiter) RetryAfter() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.retryAfter
}
