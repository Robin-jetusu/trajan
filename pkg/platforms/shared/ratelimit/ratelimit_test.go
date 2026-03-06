// pkg/platforms/shared/ratelimit/ratelimit_test.go
package ratelimit

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig_Validation tests Config struct initialization
func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "GitHub config",
			config: Config{
				HeaderPrefix:     "X-RateLimit-",
				DefaultLimit:     5000,
				DefaultRemaining: 5000,
				ThresholdPercent: 5,
				ResetDuration:    time.Hour,
			},
			valid: true,
		},
		{
			name: "GitLab config",
			config: Config{
				HeaderPrefix:     "RateLimit-",
				DefaultLimit:     2000,
				DefaultRemaining: 2000,
				ThresholdPercent: 10,
				ResetDuration:    time.Minute,
			},
			valid: true,
		},
		{
			name: "Bitbucket config",
			config: Config{
				HeaderPrefix:     "X-RateLimit-",
				DefaultLimit:     1000,
				DefaultRemaining: 1000,
				ThresholdPercent: 10,
				ResetDuration:    time.Hour,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := New(tt.config)
			assert.NotNil(t, limiter)
			assert.Equal(t, tt.config.DefaultLimit, limiter.Limit())
			assert.Equal(t, tt.config.DefaultRemaining, limiter.Remaining())
		})
	}
}

// TestLimiter_Update_WithXPrefix tests GitHub/Bitbucket header format (X-RateLimit-*)
func TestLimiter_Update_WithXPrefix(t *testing.T) {
	config := Config{
		HeaderPrefix:     "X-RateLimit-",
		DefaultLimit:     5000,
		DefaultRemaining: 5000,
		ThresholdPercent: 5,
		ResetDuration:    time.Hour,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("X-RateLimit-Remaining", "100")
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Reset", "1700000000")

	limiter.Update(header)

	assert.Equal(t, 100, limiter.Remaining())
	assert.Equal(t, 5000, limiter.Limit())
	assert.Equal(t, time.Unix(1700000000, 0), limiter.ResetTime())
}

// TestLimiter_Update_WithoutXPrefix tests GitLab header format (RateLimit-*)
func TestLimiter_Update_WithoutXPrefix(t *testing.T) {
	config := Config{
		HeaderPrefix:     "RateLimit-",
		DefaultLimit:     2000,
		DefaultRemaining: 2000,
		ThresholdPercent: 10,
		ResetDuration:    time.Minute,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("RateLimit-Remaining", "1000")
	header.Set("RateLimit-Limit", "2000")
	header.Set("RateLimit-Reset", "1735776000")

	limiter.Update(header)

	assert.Equal(t, 1000, limiter.Remaining())
	assert.Equal(t, 2000, limiter.Limit())
	assert.Equal(t, time.Unix(1735776000, 0), limiter.ResetTime())
}

// TestLimiter_ShouldThrottle_GitHub tests 5% threshold
func TestLimiter_ShouldThrottle_GitHub(t *testing.T) {
	config := Config{
		HeaderPrefix:     "X-RateLimit-",
		DefaultLimit:     5000,
		DefaultRemaining: 5000,
		ThresholdPercent: 5,
	}
	limiter := New(config)

	tests := []struct {
		name      string
		remaining int
		limit     int
		want      bool
	}{
		{
			name:      "10% remaining - should not throttle",
			remaining: 500,
			limit:     5000,
			want:      false,
		},
		{
			name:      "4% remaining - should throttle",
			remaining: 200,
			limit:     5000,
			want:      true,
		},
		{
			name:      "Exactly at 5% - should not throttle",
			remaining: 250,
			limit:     5000,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manually set values for test
			limiter.mu.Lock()
			limiter.remaining = tt.remaining
			limiter.limit = tt.limit
			limiter.mu.Unlock()

			assert.Equal(t, tt.want, limiter.ShouldThrottle())
		})
	}
}

// TestLimiter_ShouldThrottle_GitLab tests 10% threshold
func TestLimiter_ShouldThrottle_GitLab(t *testing.T) {
	config := Config{
		HeaderPrefix:     "RateLimit-",
		DefaultLimit:     2000,
		DefaultRemaining: 2000,
		ThresholdPercent: 10,
	}
	limiter := New(config)

	tests := []struct {
		name      string
		remaining int
		limit     int
		want      bool
	}{
		{
			name:      "50% remaining - should not throttle",
			remaining: 1000,
			limit:     2000,
			want:      false,
		},
		{
			name:      "At threshold (10%) - should not throttle",
			remaining: 200,
			limit:     2000,
			want:      false,
		},
		{
			name:      "Below threshold (5%) - should throttle",
			remaining: 100,
			limit:     2000,
			want:      true,
		},
		{
			name:      "Zero remaining - should throttle",
			remaining: 0,
			limit:     2000,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter.mu.Lock()
			limiter.remaining = tt.remaining
			limiter.limit = tt.limit
			limiter.mu.Unlock()

			assert.Equal(t, tt.want, limiter.ShouldThrottle())
		})
	}
}

// TestLimiter_Wait_NoThrottle tests immediate return when not throttled
func TestLimiter_Wait_NoThrottle(t *testing.T) {
	config := Config{
		DefaultLimit:     5000,
		DefaultRemaining: 5000,
		ThresholdPercent: 5,
	}
	limiter := New(config)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := limiter.Wait(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 10*time.Millisecond, "Should return immediately when not throttled")
}

// TestLimiter_Wait_ContextCanceled tests context cancellation
func TestLimiter_Wait_ContextCanceled(t *testing.T) {
	config := Config{
		DefaultLimit:     5000,
		DefaultRemaining: 100, // 2% - below 5% threshold
		ThresholdPercent: 5,
	}
	limiter := New(config)

	limiter.mu.Lock()
	limiter.remaining = 100
	limiter.limit = 5000
	limiter.reset = time.Now().Add(10 * time.Second)
	limiter.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := limiter.Wait(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestLimiter_RetryAfter tests GitHub-specific retry-after support
func TestLimiter_RetryAfter(t *testing.T) {
	config := Config{
		HeaderPrefix:       "X-RateLimit-",
		DefaultLimit:       5000,
		DefaultRemaining:   5000,
		ThresholdPercent:   5,
		SupportsRetryAfter: true,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("Retry-After", "30")

	limiter.Update(header)

	retryAfter := limiter.RetryAfter()
	assert.False(t, retryAfter.IsZero(), "RetryAfter should be set")

	expectedDuration := 30 * time.Second
	actualDuration := time.Until(retryAfter)

	// Allow 1 second tolerance
	assert.Greater(t, actualDuration, expectedDuration-time.Second)
	assert.Less(t, actualDuration, expectedDuration+time.Second)
}

// TestLimiter_Wait_RespectsRetryAfter tests retry-after waiting
func TestLimiter_Wait_RespectsRetryAfter(t *testing.T) {
	config := Config{
		DefaultLimit:       5000,
		DefaultRemaining:   5000,
		ThresholdPercent:   5,
		SupportsRetryAfter: true,
	}
	limiter := New(config)

	// Set retryAfter to 100ms in future
	limiter.mu.Lock()
	limiter.retryAfter = time.Now().Add(100 * time.Millisecond)
	limiter.mu.Unlock()

	ctx := context.Background()
	start := time.Now()
	err := limiter.Wait(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 90*time.Millisecond, "Should wait for retryAfter")
}

// TestLimiter_Wait_RetryAfterPriority tests that retry-after takes priority
func TestLimiter_Wait_RetryAfterPriority(t *testing.T) {
	config := Config{
		DefaultLimit:       5000,
		DefaultRemaining:   0,
		ThresholdPercent:   5,
		SupportsRetryAfter: true,
	}
	limiter := New(config)

	// Set primary rate limit to need long wait
	limiter.mu.Lock()
	limiter.remaining = 0
	limiter.limit = 5000
	limiter.reset = time.Now().Add(time.Hour)
	// But retryAfter is only 100ms
	limiter.retryAfter = time.Now().Add(100 * time.Millisecond)
	limiter.mu.Unlock()

	ctx := context.Background()
	start := time.Now()
	err := limiter.Wait(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	// Should wait for retryAfter (100ms), not primary reset (1 hour)
	assert.Greater(t, elapsed, 90*time.Millisecond)
	assert.Less(t, elapsed, 500*time.Millisecond)
}

// TestLimiter_Concurrent tests thread safety
func TestLimiter_Concurrent(t *testing.T) {
	config := Config{
		HeaderPrefix:     "RateLimit-",
		DefaultLimit:     2000,
		DefaultRemaining: 2000,
		ThresholdPercent: 10,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("RateLimit-Limit", "2000")
	header.Set("RateLimit-Remaining", "1000")

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			limiter.Update(header)
			_ = limiter.Remaining()
			_ = limiter.Limit()
			_ = limiter.ShouldThrottle()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify state is consistent
	assert.Equal(t, 2000, limiter.Limit())
	assert.Equal(t, 1000, limiter.Remaining())
}

// TestLimiter_Getters tests all getter methods
func TestLimiter_Getters(t *testing.T) {
	config := Config{
		DefaultLimit:     5000,
		DefaultRemaining: 4500,
		ThresholdPercent: 5,
	}
	limiter := New(config)

	resetTime := time.Now().Add(time.Hour)
	limiter.mu.Lock()
	limiter.reset = resetTime
	limiter.mu.Unlock()

	assert.Equal(t, 4500, limiter.Remaining())
	assert.Equal(t, 5000, limiter.Limit())
	assert.Equal(t, resetTime, limiter.ResetTime())
}

// TestLimiter_WithoutRetryAfter tests platforms that don't support retry-after
func TestLimiter_WithoutRetryAfter(t *testing.T) {
	config := Config{
		HeaderPrefix:       "RateLimit-",
		DefaultLimit:       2000,
		DefaultRemaining:   2000,
		ThresholdPercent:   10,
		SupportsRetryAfter: false,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("Retry-After", "30")

	// Should ignore Retry-After when not supported
	limiter.Update(header)

	retryAfter := limiter.RetryAfter()
	assert.True(t, retryAfter.IsZero(), "RetryAfter should be zero when not supported")
}
