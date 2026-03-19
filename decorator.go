package ratelimiter

import (
	"context"
	"errors"
	"time"
)

// Common rate limiter errors
var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// RateLimiterDecorator is a decorator that uses specific configuration
type RateLimiterDecorator struct {
	rateLimiter RateLimiterInterface
	enabled     bool
	bucketType  string
	limit       int
	window      time.Duration
}

// NewRateLimiterDecorator creates a rate limiter decorator
func NewRateLimiterDecorator(
	rateLimiter RateLimiterInterface,
	enabled bool,
	bucketType string,
	limit int,
	window time.Duration,
) *RateLimiterDecorator {
	return &RateLimiterDecorator{
		rateLimiter: rateLimiter,
		enabled:     enabled,
		bucketType:  bucketType,
		limit:       limit,
		window:      window,
	}
}

// CheckRateLimit checks if an action is allowed
func (r *RateLimiterDecorator) CheckRateLimit(ctx context.Context, key string) error {
	if !r.enabled {
		return nil // Rate limiting disabled
	}

	return r.rateLimiter.CheckRateLimit(ctx, key, r.bucketType, r.limit, r.window)
}

// GetBucketStatus returns the current status of the rate limit bucket
func (r *RateLimiterDecorator) GetBucketStatus(ctx context.Context, key string) (int, int, time.Time) {
	return r.rateLimiter.GetBucketStatus(ctx, key, r.bucketType)
}

// Note: RateLimiterDecorator intentionally does NOT implement RateLimiterInterface.
// It provides a simplified API with pre-configured action/limit/window parameters.
// Use the underlying RateLimiterInterface for the full API.
