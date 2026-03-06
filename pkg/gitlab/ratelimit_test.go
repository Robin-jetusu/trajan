package gitlab

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_NewRateLimiter tests default initialization
func TestRateLimiter_NewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// GitLab default rate limit is 2000 req/min (premium tier)
	assert.Equal(t, 2000, rl.Limit())
	assert.Equal(t, 2000, rl.Remaining())
	assert.False(t, rl.ResetTime().IsZero())
}

// TestRateLimiter_Update tests updating from HTTP headers with GitLab format (RateLimit-*)
func TestRateLimiter_Update(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	// GitLab uses RateLimit-* headers (NO X- prefix!)
	header.Set("RateLimit-Limit", "2000")
	header.Set("RateLimit-Remaining", "1000")
	header.Set("RateLimit-Reset", "1735776000") // 2025-01-02 00:00:00 UTC

	rl.Update(header)

	assert.Equal(t, 2000, rl.Limit())
	assert.Equal(t, 1000, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}

// TestRateLimiter_ShouldThrottle tests throttling threshold (10% for GitLab)
func TestRateLimiter_ShouldThrottle(t *testing.T) {
	tests := []struct {
		name      string
		limit     string
		remaining string
		want      bool
	}{
		{
			name:      "Above threshold (50%)",
			limit:     "2000",
			remaining: "1000",
			want:      false,
		},
		{
			name:      "At threshold (10%)",
			limit:     "2000",
			remaining: "200",
			want:      false,
		},
		{
			name:      "Below threshold (5%)",
			limit:     "2000",
			remaining: "100",
			want:      true,
		},
		{
			name:      "Very low (1%)",
			limit:     "2000",
			remaining: "20",
			want:      true,
		},
		{
			name:      "Zero remaining",
			limit:     "2000",
			remaining: "0",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter()

			header := http.Header{}
			header.Set("RateLimit-Limit", tt.limit)
			header.Set("RateLimit-Remaining", tt.remaining)
			rl.Update(header)

			assert.Equal(t, tt.want, rl.ShouldThrottle())
		})
	}
}

// TestRateLimiter_Wait tests wait behavior
func TestRateLimiter_Wait(t *testing.T) {
	t.Run("No throttle needed", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx := context.Background()

		// Set remaining above threshold via headers
		header := http.Header{}
		header.Set("RateLimit-Limit", "2000")
		header.Set("RateLimit-Remaining", "1000")
		rl.Update(header)

		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Less(t, elapsed, 10*time.Millisecond, "Should not wait when above threshold")
	})

	t.Run("Context cancellation", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx, cancel := context.WithCancel(context.Background())

		// Set to throttle
		header := http.Header{}
		header.Set("RateLimit-Limit", "2000")
		header.Set("RateLimit-Remaining", "20")
		header.Set("RateLimit-Reset", "9999999999") // Far future
		rl.Update(header)

		// Cancel immediately
		cancel()

		err := rl.Wait(ctx)
		require.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

// TestRateLimiter_Concurrent tests thread safety
func TestRateLimiter_Concurrent(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	// GitLab headers (no X- prefix)
	header.Set("RateLimit-Limit", "2000")
	header.Set("RateLimit-Remaining", "1000")

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			rl.Update(header)
			_ = rl.Remaining()
			_ = rl.Limit()
			_ = rl.ShouldThrottle()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify state is consistent
	assert.Equal(t, 2000, rl.Limit())
	assert.Equal(t, 1000, rl.Remaining())
}
