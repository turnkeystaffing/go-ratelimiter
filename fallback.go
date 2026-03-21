package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// FallbackRateLimiter wraps a primary (e.g., Redis) and fallback (e.g., in-memory) rate limiter.
// When the primary fails with infrastructure errors, it degrades to the fallback.
// Rate limit errors from the primary are returned directly (business decisions, not failures).
// Degradation requires failureThreshold consecutive infrastructure errors before triggering.
type FallbackRateLimiter struct {
	primary          RateLimiterInterface
	fallback         RateLimiterInterface
	monitor          pkgredis.DegradationMonitor
	logger           *slog.Logger
	failureThreshold int32
	failureCount     atomic.Int32
}

// NewFallbackRateLimiter creates a FallbackRateLimiter.
// failureThreshold controls how many consecutive infrastructure errors trigger degradation.
// A value <= 0 defaults to 1 (immediate degradation, original behavior).
func NewFallbackRateLimiter(
	primary RateLimiterInterface,
	fallback RateLimiterInterface,
	monitor pkgredis.DegradationMonitor,
	logger *slog.Logger,
	failureThreshold int,
) *FallbackRateLimiter {
	if primary == nil {
		panic("NewFallbackRateLimiter: primary cannot be nil")
	}
	if fallback == nil {
		panic("NewFallbackRateLimiter: fallback cannot be nil")
	}
	if monitor == nil {
		panic("NewFallbackRateLimiter: monitor cannot be nil")
	}
	if logger == nil {
		panic("NewFallbackRateLimiter: logger cannot be nil")
	}
	if failureThreshold <= 0 {
		failureThreshold = 1
	}
	return &FallbackRateLimiter{
		primary:          primary,
		fallback:         fallback,
		monitor:          monitor,
		logger:           logger,
		failureThreshold: int32(failureThreshold),
	}
}

// CheckRateLimit checks rate limits using the active limiter.
// If the primary returns *ErrRateLimited, it is returned directly (business decision).
// If the primary returns any other error, consecutive failures are tracked;
// after failureThreshold failures, the monitor is marked degraded and the fallback is used.
func (f *FallbackRateLimiter) CheckRateLimit(ctx context.Context, key string, action string, limit int, window time.Duration) error {
	if f.monitor.IsDegraded() {
		return f.fallback.CheckRateLimit(ctx, key, action, limit, window)
	}

	err := f.primary.CheckRateLimit(ctx, key, action, limit, window)
	if err == nil {
		f.failureCount.Store(0) // Reset on success
		return nil
	}

	var rateLimited *ErrRateLimited
	if errors.As(err, &rateLimited) {
		f.failureCount.Store(0) // Rate limit is a business decision, not an infra failure
		return err
	}

	// Infrastructure error — track consecutive failures
	count := f.failureCount.Add(1)
	f.logger.WarnContext(ctx, "primary rate limiter infrastructure error",
		"error_type", fmt.Sprintf("%T", err),
		"action", action,
		"consecutive_failures", count,
		"threshold", f.failureThreshold,
	)
	if count >= f.failureThreshold {
		f.monitor.MarkDegraded()
		f.failureCount.Store(0)
	}
	return f.fallback.CheckRateLimit(ctx, key, action, limit, window)
}

// GetBucketStatus delegates to the active limiter.
func (f *FallbackRateLimiter) GetBucketStatus(ctx context.Context, key string, action string) (int, int, time.Time) {
	if f.monitor.IsDegraded() {
		return f.fallback.GetBucketStatus(ctx, key, action)
	}
	return f.primary.GetBucketStatus(ctx, key, action)
}
