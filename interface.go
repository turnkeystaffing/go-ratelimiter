package ratelimiter

import (
	"context"
	"time"
)

// RateLimiterInterface defines the contract for rate limiting implementations
type RateLimiterInterface interface {
	// CheckRateLimit checks if an action is allowed under the rate limit
	CheckRateLimit(ctx context.Context, key string, action string, limit int, window time.Duration) error

	// GetBucketStatus returns the current status of a rate limit bucket for debugging
	// Returns: (current count, max limit, last refill/window start time)
	GetBucketStatus(ctx context.Context, key string, action string) (int, int, time.Time)
}

// Ensure implementations satisfy the interface
var (
	_ RateLimiterInterface       = (*RateLimiter)(nil)
	_ RateLimiterInterface       = (*RedisRateLimiter)(nil)
	_ RateLimiterInterface       = (*NoopRateLimiter)(nil)
	_ RateLimiterInterface       = (*FallbackRateLimiter)(nil)
	_ FailureTrackerInterface    = (*FailureTracker)(nil)
	_ CooldownCheckerInterface   = (*CooldownChecker)(nil)
	_ MultiCheckLimiterInterface = (*MultiCheckLimiter)(nil)
)
