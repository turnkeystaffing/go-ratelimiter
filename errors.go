package ratelimiter

import (
	"errors"
	"fmt"
	"time"
)

// ErrInvalidCooldown is returned when CheckAndSet receives a non-positive cooldown duration.
var ErrInvalidCooldown = errors.New("cooldown duration must be positive")

// Note: ErrInfrastructure.Error() intentionally returns a generic message
// to avoid leaking Redis connection details (host, port, connection state)
// in error strings that may propagate to HTTP responses. Use Unwrap() to
// access the underlying Cause for internal logging/debugging.

// ErrRateLimited is the unified rate limit error type. All rate-limited operations
// (decorator-based, service-level, domain-level) return this so that handlers can
// set RFC-required 429 headers (Retry-After, Cache-Control, X-RateLimit-*) via
// errors.As() in a single code path (HandleDecoratorRateLimitError).
type ErrRateLimited struct {
	RetryAfter time.Duration
	Limit      int
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("rate limit exceeded, retry after %s", e.RetryAfter)
}

// ErrInfrastructure is returned when the rate limit infrastructure (Redis) is
// unavailable. Handlers should check for this error via errors.As() and return
// 500/503 instead of 401 (AD-003: fail-closed returns 500, never misleading 401).
type ErrInfrastructure struct {
	Cause error
}

func (e *ErrInfrastructure) Error() string {
	return "rate limit infrastructure error"
}

func (e *ErrInfrastructure) Unwrap() error {
	return e.Cause
}
