package ratelimiter

import (
	"context"
	"fmt"
	"time"
)

// DualLayerRateLimiter implements per-client + per-IP rate limiting for OAuth/BFF endpoints.
// Both layers must pass independently for a request to be allowed.
// Per spec FR-010/FR-033, this provides DoS prevention at the endpoint level.
type DualLayerRateLimiter struct {
	baseLimiter RateLimiterInterface
	config      *DualLayerConfig
	keyPrefix   string // e.g., "oauth" or "bff"
}

// DualLayerResult contains the result of a rate limit check with details.
type DualLayerResult struct {
	Allowed       bool
	LimitType     string // "client" or "ip" - which limit was exceeded
	RetryAfter    time.Duration
	ClientCount   int
	ClientLimit   int
	IPCount       int
	IPLimit       int
	ClientResetAt time.Time
	IPResetAt     time.Time
}

// NewDualLayerRateLimiter creates a new dual-layer rate limiter.
// keyPrefix distinguishes OAuth vs BFF rate limit buckets (e.g., "oauth", "bff").
func NewDualLayerRateLimiter(
	baseLimiter RateLimiterInterface,
	config *DualLayerConfig,
	keyPrefix string,
) *DualLayerRateLimiter {
	return &DualLayerRateLimiter{
		baseLimiter: baseLimiter,
		config:      config,
		keyPrefix:   keyPrefix,
	}
}

// Check performs dual-layer rate limit check for the given endpoint.
// clientID can be empty for public endpoints (will skip client check).
// ipAddress is always required for IP-based limiting.
// Returns nil if both limits pass, ErrRateLimitExceeded if either limit is exceeded.
func (d *DualLayerRateLimiter) Check(ctx context.Context, endpoint, clientID, ipAddress string) error {
	result := d.CheckWithDetails(ctx, endpoint, clientID, ipAddress)
	if !result.Allowed {
		return ErrRateLimitExceeded
	}
	return nil
}

// CheckWithDetails performs dual-layer rate limit check and returns detailed results.
// Useful for including Retry-After headers in responses.
func (d *DualLayerRateLimiter) CheckWithDetails(ctx context.Context, endpoint, clientID, ipAddress string) *DualLayerResult {
	if !d.config.Enabled {
		return &DualLayerResult{Allowed: true}
	}

	limits := d.config.GetEndpointLimit(endpoint)
	result := &DualLayerResult{
		Allowed:     true,
		ClientLimit: limits.ClientLimit,
		IPLimit:     limits.IPLimit,
	}

	// Check per-client limit (if client ID provided and limit > 0)
	if clientID != "" && limits.ClientLimit > 0 {
		clientKey := d.clientKey(endpoint, clientID)

		err := d.baseLimiter.CheckRateLimit(ctx, clientKey, d.bucketType("client", endpoint), limits.ClientLimit, d.config.Window)
		remaining, maxLimit, resetAt := d.baseLimiter.GetBucketStatus(ctx, clientKey, d.bucketType("client", endpoint))
		// Convert remaining tokens to request count
		result.ClientCount = maxLimit - remaining
		result.ClientResetAt = resetAt

		if err != nil {
			result.Allowed = false
			result.LimitType = "client"
			result.RetryAfter = time.Until(resetAt)
			if result.RetryAfter < 0 {
				result.RetryAfter = d.config.Window
			}
			return result
		}
	}

	// Check per-IP limit (always required if limit > 0)
	if limits.IPLimit > 0 {
		ipKey := d.ipKey(endpoint, ipAddress)

		err := d.baseLimiter.CheckRateLimit(ctx, ipKey, d.bucketType("ip", endpoint), limits.IPLimit, d.config.Window)
		remaining, maxLimit, resetAt := d.baseLimiter.GetBucketStatus(ctx, ipKey, d.bucketType("ip", endpoint))
		// Convert remaining tokens to request count
		result.IPCount = maxLimit - remaining
		result.IPResetAt = resetAt

		if err != nil {
			result.Allowed = false
			result.LimitType = "ip"
			result.RetryAfter = time.Until(resetAt)
			if result.RetryAfter < 0 {
				result.RetryAfter = d.config.Window
			}
			return result
		}
	}

	return result
}

// GetStatus returns the current rate limit status for an endpoint without incrementing counters.
// Useful for debugging and monitoring.
func (d *DualLayerRateLimiter) GetStatus(ctx context.Context, endpoint, clientID, ipAddress string) *DualLayerResult {
	limits := d.config.GetEndpointLimit(endpoint)
	result := &DualLayerResult{
		Allowed:     true,
		ClientLimit: limits.ClientLimit,
		IPLimit:     limits.IPLimit,
	}

	if clientID != "" && limits.ClientLimit > 0 {
		clientKey := d.clientKey(endpoint, clientID)
		remaining, maxLimit, resetAt := d.baseLimiter.GetBucketStatus(ctx, clientKey, d.bucketType("client", endpoint))
		// Convert remaining tokens to request count
		result.ClientCount = maxLimit - remaining
		result.ClientResetAt = resetAt
		if remaining <= 0 {
			result.Allowed = false
			result.LimitType = "client"
		}
	}

	if limits.IPLimit > 0 {
		ipKey := d.ipKey(endpoint, ipAddress)
		remaining, maxLimit, resetAt := d.baseLimiter.GetBucketStatus(ctx, ipKey, d.bucketType("ip", endpoint))
		// Convert remaining tokens to request count
		result.IPCount = maxLimit - remaining
		result.IPResetAt = resetAt
		if remaining <= 0 && result.Allowed {
			result.Allowed = false
			result.LimitType = "ip"
		}
	}

	return result
}

// IsEnabled returns whether rate limiting is enabled.
func (d *DualLayerRateLimiter) IsEnabled() bool {
	return d.config.Enabled
}

// GetConfig returns the rate limit configuration.
func (d *DualLayerRateLimiter) GetConfig() *DualLayerConfig {
	return d.config
}

// clientKey generates a unique key for per-client rate limiting.
func (d *DualLayerRateLimiter) clientKey(endpoint, clientID string) string {
	return fmt.Sprintf("%s:client:%s:%s", d.keyPrefix, endpoint, clientID)
}

// ipKey generates a unique key for per-IP rate limiting.
func (d *DualLayerRateLimiter) ipKey(endpoint, ipAddress string) string {
	return fmt.Sprintf("%s:ip:%s:%s", d.keyPrefix, endpoint, ipAddress)
}

// bucketType generates the action/bucket type for the underlying rate limiter.
func (d *DualLayerRateLimiter) bucketType(layer, endpoint string) string {
	return fmt.Sprintf("%s_%s_%s", d.keyPrefix, layer, endpoint)
}
