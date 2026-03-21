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

// FailureTrackerInterface defines the contract for failure-based rate limiting.
// IsBlocked is a read-only pre-check; RecordFailure increments on failure only (FR-009).
type FailureTrackerInterface interface {
	// IsBlocked checks if a key is blocked (read-only, does not increment counter).
	IsBlocked(ctx context.Context, cfg FailureConfig) (*FailureCheckResult, error)
	// RecordFailure increments the failure counter for the given config.
	RecordFailure(ctx context.Context, cfg FailureConfig) error
}

// FailureTracker tracks failed operations per identity (client ID, user ID) and blocks
// when a threshold is exceeded. Used by service decorators for failure-based rate limiting (AD-003).
// Key design: IsBlocked is a read-only pre-check; RecordFailure increments on failure only (FR-009).
type FailureTracker struct {
	client redisclient.RedisClient
	logger *slog.Logger
}

// FailureConfig describes a failure-tracking dimension.
type FailureConfig struct {
	Prefix string        // "client", "user"
	Action string        // "token", "verify_password", "2fa_verify"
	Key    string        // client ID or user ID
	Limit  int           // max failures before blocking
	Window time.Duration // failure counting window
}

// FailureCheckResult contains the result of a failure pre-check.
type FailureCheckResult struct {
	Blocked      bool
	RetryAfter   time.Duration
	FailureCount int
	Limit        int
}

// NewFailureTracker creates a new failure-based rate limiter.
func NewFailureTracker(client redisclient.RedisClient, log *slog.Logger) *FailureTracker {
	if client == nil {
		panic("NewFailureTracker: client cannot be nil")
	}
	if log == nil {
		panic("NewFailureTracker: logger cannot be nil")
	}
	return &FailureTracker{client: client, logger: log}
}

// buildKey constructs the Redis key for a failure counter.
// Accepts a timestamp so callers can control the window alignment.
// Note: IsBlocked and RecordFailure each call time.Now() independently —
// a window-boundary race is possible (see security review S2, deferred).
func (f *FailureTracker) buildKey(cfg FailureConfig, now time.Time) string {
	windowStart := now.Truncate(cfg.Window)
	// Only Key is sanitized: Prefix and Action are developer-controlled string
	// literals set at construction time via NewFailureGuard (not user input).
	return fmt.Sprintf("rate_limit:%s:fail_%s_%s:%d",
		sanitizeKeySegment(cfg.Key),
		cfg.Prefix, cfg.Action,
		windowStart.Unix())
}

// IsBlocked checks whether the failure count for the given config has reached the limit.
// This is a read-only operation — it does NOT increment the counter.
// Fails closed on Redis errors (returns blocked).
func (f *FailureTracker) IsBlocked(ctx context.Context, cfg FailureConfig) (*FailureCheckResult, error) {
	now := time.Now()
	key := f.buildKey(cfg, now)

	result, err := f.client.Get(ctx, key)
	if err != nil {
		f.logger.WarnContext(ctx, "failure tracker pre-check failed, denying request (fail-closed)",
			"error_type", fmt.Sprintf("%T", err),
			"prefix", cfg.Prefix,
			"action", cfg.Action,
		)
		return nil, fmt.Errorf("failure tracker check failed: %w", err)
	}

	if !result.Hit {
		return &FailureCheckResult{
			Blocked:      false,
			FailureCount: 0,
			Limit:        cfg.Limit,
		}, nil
	}

	count, err := strconv.Atoi(result.Value)
	if err != nil {
		// Fail-closed: corrupt counter value is treated as blocked (conservative).
		// INCR always produces numeric values, so a non-numeric value indicates
		// data corruption or external tampering — deny request.
		f.logger.ErrorContext(ctx, "failure tracker: invalid counter value (fail-closed)",
			"prefix", cfg.Prefix,
			"action", cfg.Action,
		)
		return &FailureCheckResult{
			Blocked:      true,
			RetryAfter:   cfg.Window,
			FailureCount: 0,
			Limit:        cfg.Limit,
		}, nil
	}

	if count >= cfg.Limit {
		// Blocked — estimate retry after as the full window (conservative)
		retryAfter := cfg.Window
		windowStart := now.Truncate(cfg.Window)
		remaining := windowStart.Add(cfg.Window).Sub(now)
		if remaining > 0 {
			retryAfter = remaining
		}

		f.logger.WarnContext(ctx, "failure rate limit exceeded",
			"prefix", cfg.Prefix,
			"action", cfg.Action,
			"failure_count", count,
			"limit", cfg.Limit,
		)

		return &FailureCheckResult{
			Blocked:      true,
			RetryAfter:   retryAfter,
			FailureCount: count,
			Limit:        cfg.Limit,
		}, nil
	}

	return &FailureCheckResult{
		Blocked:      false,
		FailureCount: count,
		Limit:        cfg.Limit,
	}, nil
}

// RecordFailure increments the failure counter for the given config.
// Only call this after a service method returns a failure result.
// Successful operations MUST NOT call RecordFailure (FR-009).
func (f *FailureTracker) RecordFailure(ctx context.Context, cfg FailureConfig) error {
	key := f.buildKey(cfg, time.Now())

	pipe := f.client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, cfg.Window+time.Minute) // +1m buffer prevents mid-window key expiry at truncation boundaries

	if err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		f.logger.WarnContext(ctx, "failure tracker: failed to record failure",
			"error_type", fmt.Sprintf("%T", err),
			"prefix", cfg.Prefix,
			"action", cfg.Action,
		)
		return fmt.Errorf("failure tracker record failed: %w", err)
	}

	return nil
}
