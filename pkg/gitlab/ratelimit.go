// pkg/gitlab/ratelimit.go
package gitlab

import (
	"time"

	"github.com/praetorian-inc/trajan/pkg/platforms/shared/ratelimit"
)

// RateLimiter tracks GitLab API rate limits
// GitLab rate limit: 300-2000 requests/minute depending on tier
// Free tier: ~300 req/min, Premium/Ultimate: 2000 req/min
// Thin wrapper around shared ratelimit implementation with GitLab-specific configuration
type RateLimiter struct {
	*ratelimit.Limiter
}

// NewRateLimiter creates a new rate limiter with GitLab-specific configuration
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		Limiter: ratelimit.New(ratelimit.Config{
			HeaderPrefix:       "RateLimit-", // GitLab uses NO X- prefix
			DefaultLimit:       2000,
			DefaultRemaining:   2000,
			ThresholdPercent:   10,
			ResetDuration:      time.Minute,
			SupportsRetryAfter: false, // GitLab doesn't support secondary rate limits
		}),
	}
}
