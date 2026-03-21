package ratelimiter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIntCmd implements redisclient.IntCommand for pipeline tests.
type mockIntCmd struct {
	val int64
}

func (m *mockIntCmd) Val() int64             { return m.val }
func (m *mockIntCmd) Result() (int64, error) { return m.val, nil }

// mockBoolCmd implements redisclient.BoolCommand for pipeline tests.
type mockBoolCmd struct{}

func (m *mockBoolCmd) Val() bool             { return true }
func (m *mockBoolCmd) Result() (bool, error) { return true, nil }

// mockPipeliner implements redisclient.RedisPipeliner for testing.
type mockPipeliner struct {
	execErr error
	counter *int64 // shared counter to simulate INCR behavior
}

func (m *mockPipeliner) Incr(_ context.Context, _ string) redisclient.IntCommand {
	val := atomic.AddInt64(m.counter, 1)
	return &mockIntCmd{val: val}
}

func (m *mockPipeliner) Expire(_ context.Context, _ string, _ time.Duration) redisclient.BoolCommand {
	return &mockBoolCmd{}
}

func (m *mockPipeliner) Exec(_ context.Context) error {
	return m.execErr
}

// testRedisClient is a mock RedisClient with pipeline support for rate limiter tests.
type testRedisClient struct {
	redisclient.RedisClient
	pipeExecErr error
	counter     int64
}

func newTestRedisClient() *testRedisClient {
	return &testRedisClient{
		RedisClient: redisclient.NewMockRedisClient(),
	}
}

func (t *testRedisClient) Pipeline() redisclient.RedisPipeliner {
	return &mockPipeliner{
		execErr: t.pipeExecErr,
		counter: &t.counter,
	}
}

func (t *testRedisClient) resetCounter() {
	atomic.StoreInt64(&t.counter, 0)
}

func TestRedisRateLimiter_CheckRateLimit_WithinLimit(t *testing.T) {
	client := newTestRedisClient()
	rl := NewRedisRateLimiter(client, testNopLogger())

	err := rl.CheckRateLimit(context.Background(), "user-1", "login", 5, time.Minute)
	assert.NoError(t, err)
}

func TestRedisRateLimiter_CheckRateLimit_ExceedsLimit_ReturnsErrRateLimited(t *testing.T) {
	client := newTestRedisClient()
	rl := NewRedisRateLimiter(client, testNopLogger())

	// Use up the limit (limit=2)
	for i := 0; i < 2; i++ {
		err := rl.CheckRateLimit(context.Background(), "user-1", "login", 2, time.Minute)
		assert.NoError(t, err)
	}

	// Third request should exceed
	err := rl.CheckRateLimit(context.Background(), "user-1", "login", 2, time.Minute)
	require.Error(t, err)

	var rateLimited *ErrRateLimited
	require.True(t, errors.As(err, &rateLimited), "expected *ErrRateLimited, got %T: %v", err, err)
	assert.Equal(t, 2, rateLimited.Limit)
	assert.True(t, rateLimited.RetryAfter > 0, "RetryAfter should be positive")
}

func TestRedisRateLimiter_CheckRateLimit_PipelineError_ReturnsErrInfrastructure(t *testing.T) {
	client := newTestRedisClient()
	client.pipeExecErr = errRedis
	rl := NewRedisRateLimiter(client, testNopLogger())

	err := rl.CheckRateLimit(context.Background(), "user-1", "login", 5, time.Minute)
	require.Error(t, err)

	var infraErr *ErrInfrastructure
	require.True(t, errors.As(err, &infraErr), "expected *ErrInfrastructure, got %T: %v", err, err)
	assert.Equal(t, errRedis, infraErr.Cause)
}

func TestRedisRateLimiter_CheckRateLimit_DifferentKeys(t *testing.T) {
	client := newTestRedisClient()
	rl := NewRedisRateLimiter(client, testNopLogger())

	// Note: our mock uses a single counter, so different keys still increment the same counter.
	// This test verifies the function accepts string keys correctly.
	err := rl.CheckRateLimit(context.Background(), "user-1", "login", 5, time.Minute)
	assert.NoError(t, err)

	// Reset counter for second key
	client.resetCounter()
	err = rl.CheckRateLimit(context.Background(), "user-2", "login", 5, time.Minute)
	assert.NoError(t, err)
}
