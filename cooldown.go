package ratelimiter

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"
)

// CooldownCheckerInterface defines the contract for per-identity action cooldowns.
type CooldownCheckerInterface interface {
	// CheckAndSet atomically checks and sets a cooldown using SET NX EX.
	CheckAndSet(ctx context.Context, key, action string, cooldown time.Duration) (*CooldownCheckResult, error)
}

// CooldownControllerInterface adds explicit control of a cooldown window to CooldownCheckerInterface:
// restarting it (an action that must not be undone by a later one inside the window) and
// releasing it (an action that failed and so shouldn't block the identity).
type CooldownControllerInterface interface {
	CooldownCheckerInterface
	// Set starts or restarts the cooldown unconditionally (SET EX, no NX).
	Set(ctx context.Context, key, action string, cooldown time.Duration) error
	// Release ends the cooldown now (DEL).
	Release(ctx context.Context, key, action string) error
}

// CooldownChecker enforces per-identity action cooldowns using atomic Redis SET NX EX (AD-004).
// Used for mutation throttling (password change, 2FA setup, 2FA resend).
type CooldownChecker struct {
	client redisclient.RedisClient
	logger *slog.Logger
}

// CooldownCheckResult contains the result of a cooldown check.
type CooldownCheckResult struct {
	Blocked    bool
	RetryAfter time.Duration // remaining cooldown time (only meaningful when blocked)
}

// NewCooldownChecker creates a new cooldown checker.
func NewCooldownChecker(client redisclient.RedisClient, log *slog.Logger) *CooldownChecker {
	if client == nil {
		panic("NewCooldownChecker: client cannot be nil")
	}
	if log == nil {
		panic("NewCooldownChecker: logger cannot be nil")
	}
	return &CooldownChecker{client: client, logger: log}
}

// CheckAndSet atomically checks if a cooldown is active and sets one if not.
// Uses SET NX EX for atomicity: if the key doesn't exist, it's created with the cooldown TTL
// and the action is allowed. If the key exists, the action is blocked.
// Fails closed on Redis errors.
func (c *CooldownChecker) CheckAndSet(ctx context.Context, key, action string, cooldown time.Duration) (*CooldownCheckResult, error) {
	if cooldown <= 0 {
		return nil, ErrInvalidCooldown
	}

	redisKey := cooldownKey(key, action)

	// Atomic SET NX EX: set key only if absent, with cooldown TTL
	wasSet, err := c.client.SetNX(ctx, redisKey, "1", cooldown)
	if err != nil {
		c.logger.WarnContext(ctx, "cooldown check failed, denying request (fail-closed)",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		return nil, fmt.Errorf("cooldown check failed: %w", err)
	}

	if wasSet {
		// Key was set — action allowed, cooldown now active
		return &CooldownCheckResult{Blocked: false}, nil
	}

	// Key already exists — blocked. Get TTL for RetryAfter.
	ttl, err := c.client.TTL(ctx, redisKey)
	if err != nil {
		c.logger.WarnContext(ctx, "cooldown TTL check failed, using full cooldown as retry-after",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		// Fall back to full cooldown duration
		return &CooldownCheckResult{Blocked: true, RetryAfter: cooldown}, nil
	}

	retryAfter := ttl
	if retryAfter <= 0 {
		// Key exists but no TTL — shouldn't happen, use full cooldown
		retryAfter = cooldown
	}

	c.logger.WarnContext(ctx, "cooldown active",
		"action", action,
		"retry_after", retryAfter.Seconds(),
	)

	return &CooldownCheckResult{Blocked: true, RetryAfter: retryAfter}, nil
}

// Set starts or restarts the cooldown for key/action unconditionally (SET EX, no NX), so the
// window runs for the full duration from now even if one was already active.
func (c *CooldownChecker) Set(ctx context.Context, key, action string, cooldown time.Duration) error {
	if cooldown <= 0 {
		return ErrInvalidCooldown
	}
	if err := c.client.Set(ctx, cooldownKey(key, action), "1", cooldown); err != nil {
		c.logger.WarnContext(ctx, "cooldown set failed",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		return fmt.Errorf("cooldown set failed: %w", err)
	}
	return nil
}

// Release ends the cooldown for key/action now (DEL). Releasing a key that isn't set is not an error.
func (c *CooldownChecker) Release(ctx context.Context, key, action string) error {
	if _, err := c.client.Del(ctx, cooldownKey(key, action)); err != nil {
		c.logger.WarnContext(ctx, "cooldown release failed",
			"error_type", fmt.Sprintf("%T", err),
			"action", action,
		)
		return fmt.Errorf("cooldown release failed: %w", err)
	}
	return nil
}

// cooldownKey is the Redis key shared by CheckAndSet, Set and Release.
// Only key is sanitized: action is a developer-controlled string literal
// set at the call site (e.g., "password_change"), not user input.
func cooldownKey(key, action string) string {
	return fmt.Sprintf("rate_limit:%s:cd_%s:cooldown", sanitizeKeySegment(key), action)
}
