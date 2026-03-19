package ratelimiter

import (
	"context"
	"time"
)

// NoopRateLimiter is a no-op rate limiter that never limits
// Used for CLI commands and testing where rate limiting is not needed
type NoopRateLimiter struct{}

// NewNoopRateLimiter creates a new no-op rate limiter
func NewNoopRateLimiter() *NoopRateLimiter {
	return &NoopRateLimiter{}
}

// CheckRateLimit always returns nil (never limits)
func (n *NoopRateLimiter) CheckRateLimit(_ context.Context, _ string, _ string, _ int, _ time.Duration) error {
	return nil
}

// GetBucketStatus always returns zeros (no bucket tracking)
func (n *NoopRateLimiter) GetBucketStatus(_ context.Context, _ string, _ string) (int, int, time.Time) {
	return 0, 0, time.Time{}
}
