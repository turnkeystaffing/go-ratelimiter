package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter provides distributed rate limiting using Redis
type RedisRateLimiter struct {
	client redisclient.RedisClient
	logger *slog.Logger
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(client redisclient.RedisClient, logger *slog.Logger) *RedisRateLimiter {
	if client == nil {
		panic("NewRedisRateLimiter: client cannot be nil")
	}
	if logger == nil {
		panic("NewRedisRateLimiter: logger cannot be nil")
	}
	return &RedisRateLimiter{
		client: client,
		logger: logger,
	}
}

// buildKey constructs the base rate limit key for a key/action pair.
// Format: rate_limit:{key}:{action}
// Key segments are sanitized to prevent colon injection.
func (r *RedisRateLimiter) buildKey(key string, action string) string {
	return fmt.Sprintf("rate_limit:%s:%s", sanitizeKeySegment(key), sanitizeKeySegment(action))
}

// buildWindowKey constructs the time-windowed key for rate limiting.
// Format: rate_limit:{key}:{action}:{windowTimestamp}
func (r *RedisRateLimiter) buildWindowKey(key string, action string, windowStart time.Time) string {
	return fmt.Sprintf("%s:%d", r.buildKey(key, action), windowStart.Unix())
}

// CheckRateLimit checks if an action is allowed under the rate limit using Redis
// Uses a sliding window counter approach with Redis
func (r *RedisRateLimiter) CheckRateLimit(ctx context.Context, key string, action string, limit int, window time.Duration) error {

	// Use Redis pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Current time window start
	now := time.Now()
	windowStart := now.Truncate(window)
	windowKey := r.buildWindowKey(key, action, windowStart)

	// Increment counter - this queues the operation for execution
	incrCmd := pipe.Incr(ctx, windowKey)

	// Set expiration to prevent memory leaks (window + buffer)
	pipe.Expire(ctx, windowKey, window+time.Minute)

	// Execute pipeline atomically
	err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		r.logger.ErrorContext(ctx, "Redis rate limiter pipeline error, denying request (fail-closed)",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		return &ErrInfrastructure{Cause: err}
	}

	// Get the incremented count AFTER pipeline execution
	newCount := incrCmd.Val()

	// Check if limit exceeded
	if newCount > int64(limit) {
		r.logger.WarnContext(ctx, "Rate limit exceeded",
			"action", action,
			"count", newCount,
			"limit", limit,
			"window", window.String(),
		)
		retryAfter := windowStart.Add(window).Sub(time.Now())
		if retryAfter < 0 {
			retryAfter = window
		}
		return &ErrRateLimited{RetryAfter: retryAfter, Limit: limit}
	}

	r.logger.DebugContext(ctx, "Rate limit check passed",
		"action", action,
		"count", newCount,
		"limit", limit,
		"window", window.String(),
	)

	return nil
}

// GetBucketStatus returns the current status of a rate limit bucket for debugging
func (r *RedisRateLimiter) GetBucketStatus(ctx context.Context, key string, action string) (int, int, time.Time) {

	// Get current window
	now := time.Now()
	window := time.Hour // Default window for status check
	windowStart := now.Truncate(window)
	windowKey := r.buildWindowKey(key, action, windowStart)

	// Read from replica when available — debug status is non-critical
	result, err := r.client.ReadReplica().Get(ctx, windowKey)
	if err != nil {
		r.logger.ErrorContext(ctx, "Error getting rate limit status",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		return 0, 0, windowStart
	}
	if !result.Hit {
		// No current count, return 0
		return 0, 0, windowStart
	}

	count, err := strconv.Atoi(result.Value)
	if err != nil {
		r.logger.ErrorContext(ctx, "Error parsing rate limit count",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		return 0, 0, windowStart
	}

	// Return current tokens used, max tokens (unknown for status), and window start
	return count, 0, windowStart
}

// Cleanup is not needed for Redis implementation as Redis handles TTL automatically
func (r *RedisRateLimiter) Cleanup() {
	// Redis automatically handles cleanup via TTL, no action needed
	r.logger.DebugContext(context.Background(), "Redis rate limiter cleanup called (no action needed)")
}
