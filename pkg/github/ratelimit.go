// pkg/github/ratelimit.go
package github

import (
	"time"

	"github.com/praetorian-inc/trajan/pkg/platforms/shared/ratelimit"
)

// RateLimiter tracks GitHub API rate limits and throttles when needed
// Thin wrapper around shared ratelimit implementation with GitHub-specific configuration
type RateLimiter struct {
	*ratelimit.Limiter
}

// NewRateLimiter creates a new rate limiter with GitHub-specific configuration
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		Limiter: ratelimit.New(ratelimit.Config{
			HeaderPrefix:       "X-RateLimit-",
			DefaultLimit:       5000,
			DefaultRemaining:   5000,
			ThresholdPercent:   5,
			ResetDuration:      time.Hour,
			SupportsRetryAfter: true, // GitHub supports secondary rate limits
		}),
	}
}
