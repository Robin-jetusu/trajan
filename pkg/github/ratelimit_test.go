// pkg/github/ratelimit_test.go
package github

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_Update tests GitHub-specific header format (X-RateLimit-*)
func TestRateLimiter_Update(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	header.Set("X-RateLimit-Remaining", "100")
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Reset", "1700000000")

	rl.Update(header)

	assert.Equal(t, 100, rl.Remaining())
	assert.Equal(t, 5000, rl.Limit())
}

// TestRateLimiter_ShouldThrottle tests GitHub 5% threshold
func TestRateLimiter_ShouldThrottle(t *testing.T) {
	rl := NewRateLimiter()

	// Set values via headers
	header := http.Header{}
	header.Set("X-RateLimit-Limit", "5000")

	// 10% remaining - should not throttle
	header.Set("X-RateLimit-Remaining", "500")
	rl.Update(header)
	assert.False(t, rl.ShouldThrottle())

	// 4% remaining - should throttle
	header.Set("X-RateLimit-Remaining", "200")
	rl.Update(header)
	assert.True(t, rl.ShouldThrottle())
}

// TestRateLimiter_Wait tests immediate return when not throttled
func TestRateLimiter_Wait(t *testing.T) {
	rl := NewRateLimiter()

	// Should return immediately when not throttled
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	require.NoError(t, err)
}

// TestRateLimiter_WaitContextCanceled tests context cancellation
func TestRateLimiter_WaitContextCanceled(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	header.Set("X-RateLimit-Remaining", "100") // 2% - below 5% threshold
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Reset", "9999999999") // Far future
	rl.Update(header)

	// Should respect context cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestRateLimiter_Getters tests getter methods
func TestRateLimiter_Getters(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	header.Set("X-RateLimit-Remaining", "4500")
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Reset", "1700000000")
	rl.Update(header)

	assert.Equal(t, 4500, rl.Remaining())
	assert.Equal(t, 5000, rl.Limit())
	assert.Equal(t, time.Unix(1700000000, 0), rl.ResetTime())
}

// TestRateLimiter_UpdateWithRetryAfter tests GitHub-specific Retry-After header
func TestRateLimiter_UpdateWithRetryAfter(t *testing.T) {
	r := NewRateLimiter()

	header := http.Header{}
	header.Set("Retry-After", "30")

	r.Update(header)

	// Should have retryAfter set ~30 seconds in future
	retryAfter := r.RetryAfter()
	if retryAfter.IsZero() {
		t.Error("RetryAfter should not be zero")
	}

	expectedDuration := 30 * time.Second
	actualDuration := time.Until(retryAfter)

	// Allow 1 second tolerance
	if actualDuration < expectedDuration-time.Second || actualDuration > expectedDuration+time.Second {
		t.Errorf("RetryAfter duration = %v, want ~%v", actualDuration, expectedDuration)
	}
}

// TestRateLimiter_Wait_RespectsRetryAfter tests retry-after waiting (GitHub-specific)
func TestRateLimiter_Wait_RespectsRetryAfter(t *testing.T) {
	r := NewRateLimiter()

	// Set retryAfter via header
	header := http.Header{}
	header.Set("Retry-After", "1") // 1 second
	r.Update(header)

	ctx := context.Background()
	start := time.Now()
	err := r.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Wait() error = %v", err)
	}

	// Should have waited at least 900ms (allowing some timing slack)
	if elapsed < 900*time.Millisecond {
		t.Errorf("Wait() elapsed = %v, want >= 900ms", elapsed)
	}
}

// TestRateLimiter_Wait_RetryAfterPriorityOverPrimary tests priority (GitHub-specific)
func TestRateLimiter_Wait_RetryAfterPriority(t *testing.T) {
	r := NewRateLimiter()

	// Set primary rate limit to need long wait
	header := http.Header{}
	header.Set("X-RateLimit-Remaining", "0")
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Reset", "9999999999") // Far future
	// But retryAfter is only 1 second
	header.Set("Retry-After", "1")
	r.Update(header)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := r.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Wait() error = %v", err)
	}

	// Should wait for retryAfter (~1s), not primary reset (far future)
	if elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("Wait() elapsed = %v, want 900ms-3s (retryAfter, not primary)", elapsed)
	}
}
