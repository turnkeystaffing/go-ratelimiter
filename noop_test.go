package ratelimiter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNoopRateLimiter(t *testing.T) {
	noop := NewNoopRateLimiter()
	require.NotNil(t, noop)
}

func TestNoopRateLimiter_CheckRateLimit_AlwaysNil(t *testing.T) {
	noop := NewNoopRateLimiter()

	// Should never return an error regardless of parameters
	err := noop.CheckRateLimit(context.Background(), "user-1", "login", 1, time.Millisecond)
	assert.NoError(t, err)

	// Even with zero limit, no error (noop doesn't enforce)
	err = noop.CheckRateLimit(context.Background(), "user-1", "login", 0, time.Second)
	assert.NoError(t, err)

	// Multiple calls with same key — never limits
	for i := 0; i < 100; i++ {
		err = noop.CheckRateLimit(context.Background(), "same-key", "same-action", 1, time.Second)
		assert.NoError(t, err)
	}
}

func TestNoopRateLimiter_GetBucketStatus_ReturnsZeros(t *testing.T) {
	noop := NewNoopRateLimiter()

	count, max, resetAt := noop.GetBucketStatus(context.Background(), "user-1", "login")
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, max)
	assert.True(t, resetAt.IsZero())
}

func TestNoopRateLimiter_ImplementsInterface(t *testing.T) {
	var limiter RateLimiterInterface = NewNoopRateLimiter()
	require.NotNil(t, limiter)

	err := limiter.CheckRateLimit(context.Background(), "key", "action", 10, time.Minute)
	assert.NoError(t, err)
}
