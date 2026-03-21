package ratelimiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRateLimiterDecorator_NilRateLimiterWhenEnabled_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewRateLimiterDecorator: rateLimiter cannot be nil when enabled", func() {
		NewRateLimiterDecorator(nil, true, "login", 10, 0)
	})
}

func TestNewRateLimiterDecorator_NilRateLimiterWhenDisabled_NoPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		d := NewRateLimiterDecorator(nil, false, "login", 10, 0)
		assert.NotNil(t, d)
	})
}

func TestRateLimiterDecorator_CheckRateLimit_Delegates(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()
	d := NewRateLimiterDecorator(rl, true, "login", 2, time.Minute)

	err := d.CheckRateLimit(context.Background(), "user-1")
	assert.NoError(t, err)

	err = d.CheckRateLimit(context.Background(), "user-1")
	assert.NoError(t, err)

	// Third call should exceed the limit of 2
	err = d.CheckRateLimit(context.Background(), "user-1")
	require.Error(t, err)
	var rateLimited *ErrRateLimited
	require.True(t, errors.As(err, &rateLimited))
	assert.Equal(t, 2, rateLimited.Limit)
}

func TestRateLimiterDecorator_DisabledMode_AlwaysAllows(t *testing.T) {
	d := NewRateLimiterDecorator(nil, false, "login", 1, time.Minute)

	// Even multiple calls should succeed when disabled
	for i := 0; i < 10; i++ {
		err := d.CheckRateLimit(context.Background(), "user-1")
		assert.NoError(t, err)
	}
}

func TestRateLimiterDecorator_GetBucketStatus(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()
	d := NewRateLimiterDecorator(rl, true, "login", 5, time.Minute)

	// Before any calls
	count, max, ts := d.GetBucketStatus(context.Background(), "user-1")
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, max)
	assert.True(t, ts.IsZero())

	// After one call
	_ = d.CheckRateLimit(context.Background(), "user-1")
	count, max, _ = d.GetBucketStatus(context.Background(), "user-1")
	assert.Equal(t, 4, count) // 5 - 1 = 4 remaining
	assert.Equal(t, 5, max)
}

func TestRateLimiterDecorator_GetBucketStatus_DisabledNilLimiter(t *testing.T) {
	d := NewRateLimiterDecorator(nil, false, "login", 10, time.Minute)

	// Should not panic — returns zeros when disabled with nil limiter
	count, max, ts := d.GetBucketStatus(context.Background(), "user-1")
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, max)
	assert.True(t, ts.IsZero())
}

func TestRateLimiterDecorator_Accessors(t *testing.T) {
	d := NewRateLimiterDecorator(nil, false, "token_validation", 100, 5*time.Minute)

	assert.Equal(t, 100, d.Limit())
	assert.Equal(t, 5*time.Minute, d.Window())
}
