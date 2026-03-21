package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"

	"github.com/redis/go-redis/v9"
)

// MultiCheckLimiterInterface defines the contract for batched multi-dimension rate limit checks.
// Check atomically evaluates all dimensions in a single Redis pipeline round-trip.
type MultiCheckLimiterInterface interface {
	Check(ctx context.Context, dimensions []CheckDimension) (*MultiCheckResult, error)
}

// MultiCheckLimiter performs batched multi-dimension rate limit checks via Redis pipeline.
// Used for volume-based rate limiting (IP + email + session) in a single round-trip (AD-002).
type MultiCheckLimiter struct {
	client redisclient.RedisClient
	logger *slog.Logger
}

// CheckDimension describes a single rate limit dimension to check.
type CheckDimension struct {
	Prefix string        // "ip", "email", "session"
	Key    string        // raw identifier (IP address, normalized email, session ID)
	Action string        // endpoint name from extractor (e.g., "login", "password_reset")
	Limit  int           // 0 = skip this dimension
	Window time.Duration // rate limit window duration
}

// MultiCheckResult contains the outcome of a multi-dimension rate limit check.
type MultiCheckResult struct {
	Allowed    bool
	BlockedBy  string        // dimension prefix that caused blocking ("ip", "email", "session"), empty if allowed
	RetryAfter time.Duration // time until window resets (only meaningful when blocked)
	Limit      int           // limit of the blocking dimension (0 when Allowed=true — only meaningful when blocked)
	Remaining  int           // minimum remaining requests across all dimensions (0 when blocked; 0 when all dimensions were skipped means "no active rate limits")
}

// NewMultiCheckLimiter creates a new batched multi-dimension rate limiter.
func NewMultiCheckLimiter(client redisclient.RedisClient, log *slog.Logger) *MultiCheckLimiter {
	if client == nil {
		panic("NewMultiCheckLimiter: client cannot be nil")
	}
	if log == nil {
		panic("NewMultiCheckLimiter: logger cannot be nil")
	}
	return &MultiCheckLimiter{client: client, logger: log}
}

// Check performs batched rate limit checks across all provided dimensions.
// Dimensions with Limit=0 are skipped. All active dimensions are checked in a single
// Redis pipeline round-trip. Returns blocked if ANY dimension exceeds its limit.
// Fails closed (returns error) on Redis errors.
//
// Uses fixed-window algorithm (AD-002): windows align to time.Truncate(duration).
// Known tradeoff: requests at window boundaries can achieve up to 2x the configured
// limit in a short burst. Accepted for Redis efficiency (single INCR vs sorted set).
func (m *MultiCheckLimiter) Check(ctx context.Context, dimensions []CheckDimension) (*MultiCheckResult, error) {
	// Filter active dimensions
	active := make([]CheckDimension, 0, len(dimensions))
	for _, d := range dimensions {
		if d.Key != "" && d.Prefix != "" && d.Action != "" && d.Limit > 0 && d.Window > 0 {
			active = append(active, d)
		}
	}
	if len(active) == 0 {
		return &MultiCheckResult{Allowed: true}, nil
	}
	now := time.Now()
	pipe := m.client.Pipeline()

	type dimCmd struct {
		dim         CheckDimension
		incrCmd     redisclient.IntCommand
		windowStart time.Time
	}

	cmds := make([]dimCmd, len(active))
	for i, d := range active {
		windowStart := now.Truncate(d.Window)
		redisKey := fmt.Sprintf("rate_limit:%s:%s_%s:%d",
			sanitizeKeySegment(d.Key),
			sanitizeKeySegment(d.Prefix), sanitizeKeySegment(d.Action),
			windowStart.Unix())

		incrCmd := pipe.Incr(ctx, redisKey)
		pipe.Expire(ctx, redisKey, d.Window+time.Minute) // +1m buffer prevents mid-window key expiry at truncation boundaries

		cmds[i] = dimCmd{
			dim:         d,
			incrCmd:     incrCmd,
			windowStart: windowStart,
		}
	}

	// Execute pipeline (single round-trip)
	if err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		m.logger.ErrorContext(ctx, "rate limit pipeline failed, denying request (fail-closed)",
			"error_type", fmt.Sprintf("%T", err),
			"dimensions", len(active),
		)
		return nil, &ErrInfrastructure{Cause: fmt.Errorf("rate limit check failed: %w", err)}
	}

	// Evaluate results — find first blocked dimension
	result := &MultiCheckResult{Allowed: true}
	minRemaining := math.MaxInt

	for _, cmd := range cmds {
		val, cmdErr := cmd.incrCmd.Result()
		if cmdErr != nil {
			m.logger.WarnContext(ctx, "rate limit INCR command failed, denying request (fail-closed)",
				"error_type", fmt.Sprintf("%T", cmdErr),
				"prefix", cmd.dim.Prefix,
				"action", cmd.dim.Action,
			)
			return nil, &ErrInfrastructure{Cause: fmt.Errorf("rate limit INCR failed for %s_%s: %w", cmd.dim.Prefix, cmd.dim.Action, cmdErr)}
		}
		count := int(val)
		remaining := cmd.dim.Limit - count

		if remaining < minRemaining {
			minRemaining = remaining
		}

		// FR-025: count == limit is allowed (not retroactive), count > limit is blocked
		if count > cmd.dim.Limit && result.Allowed {
			retryAfter := cmd.windowStart.Add(cmd.dim.Window).Sub(now)
			if retryAfter <= 0 {
				retryAfter = cmd.dim.Window
			}
			result.Allowed = false
			result.BlockedBy = cmd.dim.Prefix
			result.RetryAfter = retryAfter
			result.Limit = cmd.dim.Limit
			result.Remaining = 0
			m.logger.WarnContext(ctx, "rate limit exceeded",
				"prefix", cmd.dim.Prefix,
				"action", cmd.dim.Action,
				"count", count,
				"limit", cmd.dim.Limit,
			)
		}
	}

	if result.Allowed {
		if minRemaining < 0 {
			minRemaining = 0
		}
		result.Remaining = minRemaining
	}

	return result, nil
}
