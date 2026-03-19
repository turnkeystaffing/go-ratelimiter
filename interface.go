package ratelimiter

import (
	"context"
	"time"
)

// RateLimiterInterface defines the contract for rate limiting implementations.
// All services (audit, email, document) use this single interface.
type RateLimiterInterface interface {
	// CheckRateLimit checks if an action is allowed under the rate limit.
	// Returns ErrRateLimitExceeded when limit is exceeded.
	// Returns a different error on infrastructure failures (e.g. Redis unavailable).
	// Consumers decide fail mode: audit treats any error as 429 (fail-closed),
	// email/document treat only ErrRateLimitExceeded as 429 (fail-open on infra errors).
	CheckRateLimit(ctx context.Context, key string, action string, limit int, window time.Duration) error

	// GetBucketStatus returns the current status of a rate limit bucket for debugging.
	// Returns: (current count, max limit, last refill/window start time)
	GetBucketStatus(ctx context.Context, key string, action string) (int, int, time.Time)
}

// Ensure implementations satisfy the interface
var (
	_ RateLimiterInterface = (*RateLimiter)(nil)
	_ RateLimiterInterface = (*RedisRateLimiter)(nil)
	_ RateLimiterInterface = (*NoopRateLimiter)(nil)
)
