package ratelimiter

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/turnkeystaffing/go-health"
)

// degradationDetector is implemented by FallbackRateLimiter to report degraded state.
type degradationDetector interface {
	IsDegraded() bool
}

// RateLimiterHealthChecker implements health.Checker for rate limiter degradation detection.
// When the limiter implements degradationDetector (FallbackRateLimiter), uses IsDegraded()
// directly. Otherwise falls back to probing via CheckRateLimit.
type RateLimiterHealthChecker struct {
	detector    degradationDetector // non-nil when limiter supports IsDegraded()
	log         *slog.Logger
	wasDegraded atomic.Bool
}

// NewRateLimiterHealthChecker creates a health checker that monitors rate limiter degradation.
func NewRateLimiterHealthChecker(limiter interface{}, logger *slog.Logger) *RateLimiterHealthChecker {
	if limiter == nil {
		panic("NewRateLimiterHealthChecker: limiter cannot be nil")
	}
	if logger == nil {
		panic("NewRateLimiterHealthChecker: logger cannot be nil")
	}

	checker := &RateLimiterHealthChecker{
		log: logger,
	}

	if d, ok := limiter.(degradationDetector); ok {
		checker.detector = d
	}

	return checker
}

// Check implements health.Checker.
func (c *RateLimiterHealthChecker) Check(_ context.Context) health.CheckResult {
	start := time.Now()
	result := health.CheckResult{
		Name:      "rate_limiter",
		Timestamp: start,
	}

	degraded := false
	if c.detector != nil {
		degraded = c.detector.IsDegraded()
	}

	if degraded {
		result.Status = health.CheckWarn
		result.Error = "rate limiter running in degraded mode (Redis unavailable, using in-memory fallback)"

		// Log transition: healthy → degraded (once)
		if !c.wasDegraded.Swap(true) {
			c.log.Warn("Rate limiter degraded, using in-memory fallback")
		}
	} else {
		result.Status = health.CheckPass

		// Log transition: degraded → healthy (once)
		if c.wasDegraded.Swap(false) {
			c.log.Info("Rate limiter recovered, resuming Redis")
		}
	}

	result.Duration = time.Since(start)
	return result
}

var _ health.Checker = (*RateLimiterHealthChecker)(nil)
