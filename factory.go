package ratelimiter

import (
	"fmt"
	"log/slog"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"
)

// Config holds rate limiting configuration parameters.
// This allows pkg/ratelimiter to be independent of internal config packages.
type Config struct {
	Enabled               bool
	LoginLimit            int
	LoginWindow           time.Duration
	TokenValidationLimit  int
	TokenValidationWindow time.Duration
	DefaultLimit          int
	DefaultWindow         time.Duration
}

// NewRateLimiterFromRedis creates a Redis-based distributed rate limiter.
// Returns error on nil client.
func NewRateLimiterFromRedis(redisClient redisclient.RedisClient, logger *slog.Logger) (RateLimiterInterface, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis client is required for distributed rate limiting")
	}
	logger.Info("Initializing Redis-based distributed rate limiter")
	return NewRedisRateLimiter(redisClient, logger), nil
}

// NewRateLimiterFromMemory creates an in-memory rate limiter (not suitable for distributed deployments)
func NewRateLimiterFromMemory(logger *slog.Logger) RateLimiterInterface {
	logger.Warn("Using in-memory rate limiter - not suitable for distributed deployments")
	return NewRateLimiter()
}

// NewLoginRateLimiterFromConfig creates a login-specific rate limiter from configuration
func NewLoginRateLimiterFromConfig(baseLimiter RateLimiterInterface, cfg *Config, logger *slog.Logger) (*RateLimiterDecorator, error) {
	return createRateLimiterDecorator(
		baseLimiter, logger, cfg,
		"login",
		cfg.LoginLimit,
		cfg.LoginWindow,
		"enabled", cfg.Enabled,
		"login_limit", cfg.LoginLimit,
		"login_window", cfg.LoginWindow,
	)
}

// NewTokenValidationRateLimiterFromConfig creates a token validation rate limiter from configuration
func NewTokenValidationRateLimiterFromConfig(baseLimiter RateLimiterInterface, cfg *Config, logger *slog.Logger) (*RateLimiterDecorator, error) {
	return createRateLimiterDecorator(
		baseLimiter, logger, cfg,
		"token_validation",
		cfg.TokenValidationLimit,
		cfg.TokenValidationWindow,
		"enabled", cfg.Enabled,
		"token_validation_limit", cfg.TokenValidationLimit,
		"token_validation_window", cfg.TokenValidationWindow,
	)
}

// NewDefaultRateLimiterFromConfig creates a default rate limiter from configuration
func NewDefaultRateLimiterFromConfig(bucketType string, baseLimiter RateLimiterInterface, cfg *Config, logger *slog.Logger) (*RateLimiterDecorator, error) {
	return createRateLimiterDecorator(
		baseLimiter, logger, cfg,
		bucketType,
		cfg.DefaultLimit,
		cfg.DefaultWindow,
		"enabled", cfg.Enabled,
		"default_limit", cfg.DefaultLimit,
		"default_window", cfg.DefaultWindow,
	)
}

// createRateLimiterDecorator is a DRY helper for creating rate limiter decorators
func createRateLimiterDecorator(
	baseLimiter RateLimiterInterface,
	logger *slog.Logger,
	cfg *Config,
	bucketType string,
	limit int,
	window time.Duration,
	logFields ...any,
) (*RateLimiterDecorator, error) {
	logger.Info("Initializing "+bucketType+" rate limiter", logFields...)

	// Fallback to defaults if not set
	if limit <= 0 {
		limit = cfg.DefaultLimit
	}
	if window <= 0 {
		window = cfg.DefaultWindow
	}

	return NewRateLimiterDecorator(
		baseLimiter,
		cfg.Enabled,
		bucketType,
		limit,
		window,
	), nil
}
