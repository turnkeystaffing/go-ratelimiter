package ratelimiter

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// FailureGuard is a pre-configured failure tracker that owns the entire
// rate-limit flow: pre-check → execute → record failure on error.
// Constructed once with static config (prefix, action, limit, window);
// only the dynamic key varies per call.
// Safe for concurrent use: Guard copies cfg by value before mutating Key.
type FailureGuard struct {
	tracker FailureTrackerInterface
	cfg     FailureConfig // pre-built template (Key is set per-call)
	logger  *slog.Logger
}

// NewFailureGuard creates a FailureGuard with pre-configured rate limit parameters.
// The returned guard is safe for concurrent use.
func NewFailureGuard(
	tracker FailureTrackerInterface,
	prefix, action string,
	limit int,
	window time.Duration,
	log *slog.Logger,
) *FailureGuard {
	if tracker == nil {
		panic("NewFailureGuard: tracker cannot be nil")
	}
	if log == nil {
		panic("NewFailureGuard: logger cannot be nil")
	}
	if prefix == "" {
		panic("NewFailureGuard: prefix cannot be empty")
	}
	if action == "" {
		panic("NewFailureGuard: action cannot be empty")
	}
	if limit <= 0 {
		panic("NewFailureGuard: limit must be positive")
	}
	if window <= 0 {
		panic("NewFailureGuard: window must be positive")
	}
	return &FailureGuard{
		tracker: tracker,
		cfg: FailureConfig{
			Prefix: prefix,
			Action: action,
			Limit:  limit,
			Window: window,
		},
		logger: log,
	}
}

// Guard wraps an operation with failure-based rate limiting.
// Flow: pre-check (IsBlocked) → execute fn → record failure if fn returns error.
//
// Returns:
//   - zero value + *ErrRateLimited if the key is blocked (too many prior failures)
//   - zero value + *ErrInfrastructure if Redis is unavailable (fail-closed, AD-003)
//   - The result and error from fn (after recording failure if fn returned error)
func Guard[T any](g *FailureGuard, ctx context.Context, key string, fn func() (T, error)) (T, error) {
	cfg := g.cfg
	cfg.Key = key

	var zero T

	// Pre-check: is this key already blocked?
	result, err := g.tracker.IsBlocked(ctx, cfg)
	if err != nil {
		g.logger.WarnContext(ctx, "rate limit pre-check failed (fail-closed)",
			"error_type", fmt.Sprintf("%T", err),
			"prefix", cfg.Prefix,
			"action", cfg.Action,
		)
		return zero, &ErrInfrastructure{Cause: err}
	}
	if result.Blocked {
		// FailureTracker.IsBlocked already logs the blocked event — no duplicate log here
		return zero, &ErrRateLimited{RetryAfter: result.RetryAfter, Limit: result.Limit}
	}

	// Execute the guarded operation
	val, fnErr := fn()
	if fnErr != nil {
		// Record failure (FR-009: only failures increment counter)
		if recordErr := g.tracker.RecordFailure(ctx, cfg); recordErr != nil {
			g.logger.WarnContext(ctx, "failed to record failure",
				"error_type", fmt.Sprintf("%T", recordErr),
				"prefix", cfg.Prefix,
				"action", cfg.Action,
			)
			// Still return the original error — recording is best-effort
		}
		return val, fnErr
	}

	// Success: do NOT record anything (FR-009)
	return val, nil
}
