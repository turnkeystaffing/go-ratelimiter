package ratelimiter

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// FallbackRateLimiter wraps a primary (Redis) and fallback (in-memory) rate limiter.
// During normal operation, all requests go to the primary. When the primary returns
// an infrastructure error, the shared DegradationMonitor is notified and subsequent
// requests go to the fallback until the monitor recovers.
type FallbackRateLimiter struct {
	primary  RateLimiterInterface
	fallback RateLimiterInterface
	monitor  pkgredis.DegradationMonitor
	log      *slog.Logger
}

// NewFallbackRateLimiter creates a rate limiter that falls back to an in-memory
// implementation when the primary (Redis) is unavailable. The monitor is shared
// across all Redis consumers — a single probe handles recovery for all.
func NewFallbackRateLimiter(primary, fallback RateLimiterInterface, monitor pkgredis.DegradationMonitor, logger *slog.Logger) *FallbackRateLimiter {
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
	return &FallbackRateLimiter{
		primary:  primary,
		fallback: fallback,
		monitor:  monitor,
		log:      logger,
	}
}

// CheckRateLimit checks the rate limit using the primary or fallback limiter.
func (f *FallbackRateLimiter) CheckRateLimit(ctx context.Context, key string, action string, limit int, window time.Duration) error {
	if f.monitor.IsDegraded() {
		return f.fallback.CheckRateLimit(ctx, key, action, limit, window)
	}

	err := f.primary.CheckRateLimit(ctx, key, action, limit, window)
	if err == nil || errors.Is(err, ErrRateLimitExceeded) {
		return err
	}

	// Primary infrastructure error — notify monitor, fall back
	f.monitor.MarkDegraded()
	f.log.Warn("Rate limiter primary unavailable, falling back to in-memory",
		slog.String("error", err.Error()))
	return f.fallback.CheckRateLimit(ctx, key, action, limit, window)
}

// GetBucketStatus returns bucket status from the active limiter.
func (f *FallbackRateLimiter) GetBucketStatus(ctx context.Context, key string, action string) (int, int, time.Time) {
	if f.monitor.IsDegraded() {
		return f.fallback.GetBucketStatus(ctx, key, action)
	}
	return f.primary.GetBucketStatus(ctx, key, action)
}

// IsDegraded returns true when the fallback (in-memory) limiter is active.
func (f *FallbackRateLimiter) IsDegraded() bool {
	return f.monitor.IsDegraded()
}

// Close closes both limiters if they implement io.Closer.
func (f *FallbackRateLimiter) Close() error {
	if c, ok := f.primary.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	if c, ok := f.fallback.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	return nil
}
