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
	return &RedisRateLimiter{
		client: client,
		logger: logger,
	}
}

// buildKey constructs the base rate limit key for a key/action pair.
// Format: rate_limit:{key}:{action}
func (r *RedisRateLimiter) buildKey(key string, action string) string {
	return fmt.Sprintf("rate_limit:%s:%s", key, action)
}

// buildWindowKey constructs the time-windowed key for rate limiting.
// Format: rate_limit:{key}:{action}:{windowTimestamp}
func (r *RedisRateLimiter) buildWindowKey(key string, action string, windowStart time.Time) string {
	return fmt.Sprintf("%s:%d", r.buildKey(key, action), windowStart.Unix())
}

// CheckRateLimit checks if an action is allowed under the rate limit using Redis.
// Returns ErrRateLimitExceeded when limit is exceeded.
// Returns a wrapped infrastructure error when Redis is unavailable.
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
		r.logger.Error("Redis rate limiter pipeline error",
			"error", err.Error(),
			"key", key,
			"action", action,
			"window_key", windowKey,
		)
		return fmt.Errorf("rate limiter unavailable: %w", err)
	}

	// Get the incremented count AFTER pipeline execution
	newCount := incrCmd.Val()

	// Check if limit exceeded
	if newCount > int64(limit) {
		r.logger.Warn("Rate limit exceeded",
			"key", key,
			"action", action,
			"count", newCount,
			"limit", limit,
			"window", window.String(),
		)
		return ErrRateLimitExceeded
	}

	r.logger.Debug("Rate limit check passed",
		"key", key,
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
		r.logger.Error("Error getting rate limit status",
			"error", err.Error(),
			"key", key,
			"action", action,
			"window_key", windowKey,
		)
		return 0, 0, windowStart
	}
	if !result.Hit {
		// No current count, return 0
		return 0, 0, windowStart
	}

	count, err := strconv.Atoi(result.Value)
	if err != nil {
		r.logger.Error("Error parsing rate limit count",
			"error", err.Error(),
			"count_str", result.Value,
			"key", key,
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
	r.logger.Debug("Redis rate limiter cleanup called (no action needed)")
}
