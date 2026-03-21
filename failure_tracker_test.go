package ratelimiter

import (
	"context"
	"fmt"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	redisclient "github.com/turnkeystaffing/go-redis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFailureClient is a mock RedisClient with configurable Get() and Pipeline() for FailureTracker tests.
type testFailureClient struct {
	redisclient.RedisClient // embed for unused methods (delegates to MockRedisClient)
	getResult               *redisclient.CacheResult
	getErr                  error
	pipeExecErr             error
	counter                 int64
}

func newTestFailureClient() *testFailureClient {
	return &testFailureClient{
		RedisClient: redisclient.NewMockRedisClient(),
		getResult:   &redisclient.CacheResult{Hit: false},
	}
}

func (c *testFailureClient) Get(_ context.Context, _ string) (redisclient.CacheResult, error) {
	if c.getErr != nil {
		return redisclient.CacheResult{}, c.getErr
	}
	if c.getResult != nil {
		return *c.getResult, nil
	}
	return redisclient.CacheResult{Hit: false}, nil
}

func (c *testFailureClient) Pipeline() redisclient.RedisPipeliner {
	return &mockPipeliner{
		execErr: c.pipeExecErr,
		counter: &c.counter,
	}
}

// --- IsBlocked tests ---

func TestFailureTracker_IsBlocked_NotBlocked_NoKey(t *testing.T) {
	client := newTestFailureClient()
	client.getResult = &redisclient.CacheResult{Hit: false}

	tracker := NewFailureTracker(client, testNopLogger())

	result, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 0, result.FailureCount)
	assert.Equal(t, 10, result.Limit)
}

func TestFailureTracker_IsBlocked_NotBlocked_UnderLimit(t *testing.T) {
	client := newTestFailureClient()
	client.getResult = &redisclient.CacheResult{Value: "3", Hit: true}

	tracker := NewFailureTracker(client, testNopLogger())

	result, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 3, result.FailureCount)
	assert.Equal(t, 10, result.Limit)
}

func TestFailureTracker_IsBlocked_Blocked_AtLimit(t *testing.T) {
	client := newTestFailureClient()
	client.getResult = &redisclient.CacheResult{Value: "10", Hit: true}

	tracker := NewFailureTracker(client, testNopLogger())

	result, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.True(t, result.RetryAfter > 0, "expected positive RetryAfter when blocked")
	assert.Equal(t, 10, result.FailureCount)
	assert.Equal(t, 10, result.Limit)
}

func TestFailureTracker_IsBlocked_Blocked_AtLimitOne(t *testing.T) {
	client := newTestFailureClient()
	client.getResult = &redisclient.CacheResult{Value: "1", Hit: true}

	tracker := NewFailureTracker(client, testNopLogger())

	result, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "user", Action: "2fa_verify", Key: "user-789",
		Limit: 1, Window: time.Minute,
	})

	require.NoError(t, err)
	assert.True(t, result.Blocked, "expected blocked when count (1) reaches limit (1)")
	assert.Equal(t, 1, result.FailureCount)
	assert.Equal(t, 1, result.Limit)
	assert.True(t, result.RetryAfter > 0, "expected positive RetryAfter when blocked")
}

func TestFailureTracker_IsBlocked_Blocked_OverLimit(t *testing.T) {
	client := newTestFailureClient()
	client.getResult = &redisclient.CacheResult{Value: "15", Hit: true}

	tracker := NewFailureTracker(client, testNopLogger())

	result, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "user", Action: "verify_password", Key: "user-456",
		Limit: 5, Window: 15 * time.Minute,
	})

	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, 15, result.FailureCount)
	assert.Equal(t, 5, result.Limit)
}

func TestFailureTracker_IsBlocked_FailClosed_RedisError(t *testing.T) {
	client := newTestFailureClient()
	client.getErr = errRedis

	tracker := NewFailureTracker(client, testNopLogger())

	_, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.Error(t, err, "expected error on Redis failure (fail-closed)")
	assert.ErrorIs(t, err, errRedis, "expected error to wrap original Redis error")
}

func TestFailureTracker_IsBlocked_InvalidCounterValue_FailClosed(t *testing.T) {
	client := newTestFailureClient()
	client.getResult = &redisclient.CacheResult{Value: "not-a-number", Hit: true}

	tracker := NewFailureTracker(client, testNopLogger())

	result, err := tracker.IsBlocked(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.NoError(t, err)
	assert.True(t, result.Blocked, "expected blocked on invalid counter value (fail-closed)")
	assert.True(t, result.RetryAfter > 0, "expected positive RetryAfter when blocked due to corrupt counter")
	assert.Equal(t, 10, result.Limit)
}

// --- RecordFailure tests ---

func TestFailureTracker_RecordFailure_Success(t *testing.T) {
	client := newTestFailureClient()
	tracker := NewFailureTracker(client, testNopLogger())

	err := tracker.RecordFailure(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.NoError(t, err)
	// counter is incremented by mockPipeliner.Incr() (defined in redis_ratelimiter_test.go)
	assert.Equal(t, int64(1), client.counter, "expected pipeline INCR to increment counter")
}

func TestFailureTracker_RecordFailure_RedisError(t *testing.T) {
	client := newTestFailureClient()
	client.pipeExecErr = errRedis
	tracker := NewFailureTracker(client, testNopLogger())

	err := tracker.RecordFailure(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.Error(t, err, "expected error on Redis failure")
	assert.ErrorIs(t, err, errRedis, "expected error to wrap original Redis error")
}

func TestFailureTracker_RecordFailure_RedisNil_TreatedAsSuccess(t *testing.T) {
	client := newTestFailureClient()
	client.pipeExecErr = redis.Nil // redis.Nil is explicitly excluded from error handling
	tracker := NewFailureTracker(client, testNopLogger())

	err := tracker.RecordFailure(context.Background(), FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	})

	require.NoError(t, err, "redis.Nil from pipeline should be treated as success (INCR on missing key)")
}

// --- buildKey tests (same-package access to unexported method) ---

func TestFailureTracker_BuildKey_Format(t *testing.T) {
	client := newTestFailureClient()
	tracker := NewFailureTracker(client, testNopLogger())

	fixedTime := time.Date(2024, 3, 20, 10, 0, 0, 0, time.UTC)
	key := tracker.buildKey(FailureConfig{
		Prefix: "client", Action: "token", Key: "client-123",
		Limit: 10, Window: time.Minute,
	}, fixedTime)

	windowStart := fixedTime.Truncate(time.Minute).Unix()
	expected := fmt.Sprintf("rate_limit:client-123:fail_client_token:%d", windowStart)
	assert.Equal(t, expected, key)

	// Verify no auth_ prefix
	assert.NotContains(t, key, "auth_", "key should not contain auth_ prefix")
	// Verify uses plain string, not UUID
	assert.Contains(t, key, "client-123", "key should contain plain key string")
}

func TestFailureTracker_BuildKey_SanitizesColons(t *testing.T) {
	client := newTestFailureClient()
	tracker := NewFailureTracker(client, testNopLogger())

	fixedTime := time.Date(2024, 3, 20, 10, 0, 0, 0, time.UTC)
	key := tracker.buildKey(FailureConfig{
		Prefix: "client", Action: "token", Key: "::1",
		Limit: 10, Window: time.Minute,
	}, fixedTime)

	// Colons in key should be escaped to %3A
	assert.Contains(t, key, "%3A%3A1", "colons in key segment should be escaped")
	assert.NotContains(t, key, ":::", "raw colons should not appear in key segment")
}

func TestFailureTracker_BuildKey_EmptyKey(t *testing.T) {
	client := newTestFailureClient()
	tracker := NewFailureTracker(client, testNopLogger())

	fixedTime := time.Date(2024, 3, 20, 10, 0, 0, 0, time.UTC)
	key := tracker.buildKey(FailureConfig{
		Prefix: "client", Action: "token", Key: "",
		Limit: 10, Window: time.Minute,
	}, fixedTime)

	// Empty key produces an empty segment — all empty-key callers share one bucket.
	// This is by design: the library does not validate business-level key semantics.
	windowStart := fixedTime.Truncate(time.Minute).Unix()
	expected := fmt.Sprintf("rate_limit::fail_client_token:%d", windowStart)
	assert.Equal(t, expected, key)
}

// --- Constructor nil-check tests ---

func TestNewFailureTracker_PanicsOnNilClient(t *testing.T) {
	require.Panics(t, func() {
		NewFailureTracker(nil, testNopLogger())
	})
}

func TestNewFailureTracker_PanicsOnNilLogger(t *testing.T) {
	require.Panics(t, func() {
		NewFailureTracker(newTestFailureClient(), nil)
	})
}
