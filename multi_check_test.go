package ratelimiter

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	redisclient "github.com/turnkeystaffing/go-redis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMultiCheckClient is a mock RedisClient for MultiCheckLimiter tests.
// Uses a shared atomic counter to simulate per-key INCR behavior.
type testMultiCheckClient struct {
	redisclient.RedisClient
	pipeExecErr error
	counter     int64
}

func newTestMultiCheckClient() *testMultiCheckClient {
	return &testMultiCheckClient{
		RedisClient: redisclient.NewMockRedisClient(),
	}
}

func (c *testMultiCheckClient) Pipeline() redisclient.RedisPipeliner {
	return &mockPipeliner{
		execErr: c.pipeExecErr,
		counter: &c.counter,
	}
}

// captureMultiCheckPipeliner captures all Redis keys passed to Incr, keys passed to Expire,
// and TTLs passed to Expire for format and TTL assertions.
// Not thread-safe for concurrent use — designed for sequential tests only.
type captureMultiCheckPipeliner struct {
	capturedKeys       []string
	capturedExpireKeys []string
	capturedTTLs       []time.Duration
	counter            int64
	execErr            error
}

func (p *captureMultiCheckPipeliner) Incr(_ context.Context, key string) redisclient.IntCommand {
	p.capturedKeys = append(p.capturedKeys, key)
	p.counter++
	return &mockIntCmd{val: p.counter}
}

func (p *captureMultiCheckPipeliner) Expire(_ context.Context, key string, ttl time.Duration) redisclient.BoolCommand {
	p.capturedExpireKeys = append(p.capturedExpireKeys, key)
	p.capturedTTLs = append(p.capturedTTLs, ttl)
	return &mockBoolCmd{}
}

func (p *captureMultiCheckPipeliner) Exec(_ context.Context) error {
	return p.execErr
}

type captureMultiCheckClient struct {
	redisclient.RedisClient
	pipeliner *captureMultiCheckPipeliner
}

func newCaptureMultiCheckClient() *captureMultiCheckClient {
	return &captureMultiCheckClient{
		RedisClient: redisclient.NewMockRedisClient(),
		pipeliner:   &captureMultiCheckPipeliner{},
	}
}

func (c *captureMultiCheckClient) Pipeline() redisclient.RedisPipeliner {
	return c.pipeliner
}

type errorIncrClient struct {
	redisclient.RedisClient
	pipeliner *errorIncrPipeliner
}

func (c *errorIncrClient) Pipeline() redisclient.RedisPipeliner { return c.pipeliner }

// partialErrorPipeliner succeeds for the first successCount INCR calls, then returns errors.
// Simulates partial pipeline failure (e.g., WRONGTYPE on one key but not others).
type partialErrorPipeliner struct {
	successCount int
	callCount    int
	counter      int64
	incrErr      error
}

func (p *partialErrorPipeliner) Incr(_ context.Context, _ string) redisclient.IntCommand {
	p.callCount++
	if p.callCount <= p.successCount {
		p.counter++
		return &mockIntCmd{val: p.counter}
	}
	return &mockErrorIntCmd{err: p.incrErr}
}

func (p *partialErrorPipeliner) Expire(_ context.Context, _ string, _ time.Duration) redisclient.BoolCommand {
	return &mockBoolCmd{}
}

func (p *partialErrorPipeliner) Exec(_ context.Context) error { return nil }

type partialErrorClient struct {
	redisclient.RedisClient
	pipeliner *partialErrorPipeliner
}

func (c *partialErrorClient) Pipeline() redisclient.RedisPipeliner { return c.pipeliner }

// --- Unit tests ---

func TestMultiCheckLimiter_Check_AllUnderLimit(t *testing.T) {
	// AC2 + AC5: 3 dimensions all under limit → Allowed=true, Remaining reflects min
	client := newTestMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Empty(t, result.BlockedBy)
	// Counter increments: ip=1, email=2, session=3
	// Remaining: min(30-1, 5-2, 10-3) = min(29, 3, 7) = 3
	assert.Equal(t, 3, result.Remaining)
}

func TestMultiCheckLimiter_Check_OneDimensionExceedsLimit(t *testing.T) {
	// AC3: email exceeds → Allowed=false, BlockedBy="email", RetryAfter>0, Remaining=0
	client := newTestMultiCheckClient()
	// Pre-set counter so email (second dim) exceeds limit=5 → counter=1(ip), then 2(email)
	// We need email count > 5. Set counter to 4 so: ip=5, email=6 (exceeds 5)
	atomic.StoreInt64(&client.counter, 4)
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "email", result.BlockedBy)
	assert.True(t, result.RetryAfter > 0, "RetryAfter should be positive when blocked")
	assert.LessOrEqual(t, result.RetryAfter, time.Minute, "RetryAfter should not exceed the dimension's Window")
	assert.Equal(t, 0, result.Remaining)
}

func TestMultiCheckLimiter_Check_ZeroLimitDimensionSkipped(t *testing.T) {
	// AC4: Limit=0 dimension not sent to Redis
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 0, Window: time.Minute}, // skipped
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	// Only 2 keys captured (email skipped)
	assert.Len(t, client.pipeliner.capturedKeys, 2)
	for _, key := range client.pipeliner.capturedKeys {
		assert.NotContains(t, key, "email", "zero-limit email dimension should be skipped")
	}
}

func TestMultiCheckLimiter_Check_AllZeroLimitDimensions(t *testing.T) {
	// AC4: all Limit=0 → Allowed=true immediately without Redis call
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 0, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 0, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 0, "no Redis calls for all-zero dimensions")
}

func TestMultiCheckLimiter_Check_EmptyDimensions(t *testing.T) {
	// AC4 edge case: empty slice → Allowed=true immediately
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	result, err := limiter.Check(context.Background(), []CheckDimension{})

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 0, "no Redis calls for empty dimensions")
}

func TestMultiCheckLimiter_Check_ZeroWindowDimensionSkipped(t *testing.T) {
	// Dimensions with Window <= 0 should be skipped (same as Limit=0)
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: 0},          // skipped
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 10, Window: -time.Second}, // skipped
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 1, "only ip dimension should be sent to Redis")
	assert.Contains(t, client.pipeliner.capturedKeys[0], "ip_login")
}

func TestMultiCheckLimiter_Check_CountEqualsLimit_Allowed(t *testing.T) {
	// AC6: count==limit is allowed (FR-025)
	client := newTestMultiCheckClient()
	// Set counter so INCR returns exactly limit (5)
	atomic.StoreInt64(&client.counter, 4) // next INCR → 5
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed, "count==limit should be allowed per FR-025")
	assert.Equal(t, 0, result.Remaining)
}

func TestMultiCheckLimiter_Check_CountExceedsLimit_Blocked(t *testing.T) {
	// AC6 boundary complement: count>limit is blocked
	client := newTestMultiCheckClient()
	// Set counter so INCR returns limit+1 (6)
	atomic.StoreInt64(&client.counter, 5) // next INCR → 6
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.False(t, result.Allowed, "count>limit should be blocked")
	assert.Equal(t, "email", result.BlockedBy)
	assert.Equal(t, 0, result.Remaining)
}

func TestMultiCheckLimiter_Check_FailClosed_PipelineError(t *testing.T) {
	// AC7: pipeline Exec returns error → returns error (fail-closed)
	client := newTestMultiCheckClient()
	client.pipeExecErr = errRedis
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, errRedis)
	var infraErr *ErrInfrastructure
	assert.True(t, errors.As(err, &infraErr), "pipeline error should be wrapped in ErrInfrastructure")
}

func TestMultiCheckLimiter_Check_KeyFormat(t *testing.T) {
	// AC8: key format rate_limit:{sanitized}:{prefix}_{action}:{unix}
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
	}

	_, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	require.Len(t, client.pipeliner.capturedKeys, 1)

	key := client.pipeliner.capturedKeys[0]
	assert.True(t, strings.HasPrefix(key, "rate_limit:"), "key should start with rate_limit:")
	assert.Contains(t, key, "user@example.com")
	assert.Contains(t, key, "email_login")
	assert.NotContains(t, key, "auth_", "key should not contain auth_ prefix")
	// Verify 4-segment format: rate_limit:{key}:{prefix_action}:{timestamp}
	parts := strings.SplitN(key, ":", 4)
	assert.Len(t, parts, 4, "key should have 4 colon-separated segments")

	// Verify Expire targets the same key as Incr
	require.Len(t, client.pipeliner.capturedExpireKeys, 1)
	assert.Equal(t, client.pipeliner.capturedKeys[0], client.pipeliner.capturedExpireKeys[0], "Expire key must match Incr key")

	// Verify Expire TTL = Window + 1 minute buffer
	require.Len(t, client.pipeliner.capturedTTLs, 1)
	assert.Equal(t, time.Minute+time.Minute, client.pipeliner.capturedTTLs[0], "Expire TTL should be Window + 1 minute buffer")
}

func TestMultiCheckLimiter_Check_KeyFormat_TTL_DifferentWindow(t *testing.T) {
	// Adversarial P2 F8: verify TTL = Window + 1 minute for non-1-minute Window
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: 5 * time.Minute},
	}

	_, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	require.Len(t, client.pipeliner.capturedTTLs, 1)
	assert.Equal(t, 5*time.Minute+time.Minute, client.pipeliner.capturedTTLs[0], "Expire TTL should be 5min Window + 1min buffer = 6min")
}

func TestMultiCheckLimiter_Check_KeyFormat_SanitizesColons(t *testing.T) {
	// AC9: key with ::1 produces %3A%3A1 in key segment
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "::1", Action: "login", Limit: 30, Window: time.Minute},
	}

	_, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	require.Len(t, client.pipeliner.capturedKeys, 1)

	key := client.pipeliner.capturedKeys[0]
	assert.Contains(t, key, "%3A%3A1", "colons in key segment should be escaped")
	// The key segment should not contain raw colons from the IPv6 address
	// Split on "rate_limit:" to get the rest, then check the key segment
	afterPrefix := strings.TrimPrefix(key, "rate_limit:")
	keySegment := strings.SplitN(afterPrefix, ":", 2)[0]
	assert.Equal(t, "%3A%3A1", keySegment)
}

func TestMultiCheckLimiter_Check_KeyFormat_MultipleDimensions(t *testing.T) {
	// AC8: each dimension produces its own correctly formatted key
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 10, Window: time.Minute},
	}

	_, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	require.Len(t, client.pipeliner.capturedKeys, 3)

	assert.Contains(t, client.pipeliner.capturedKeys[0], "ip_login")
	assert.Contains(t, client.pipeliner.capturedKeys[0], "192.168.1.1")

	assert.Contains(t, client.pipeliner.capturedKeys[1], "email_login")
	assert.Contains(t, client.pipeliner.capturedKeys[1], "user@example.com")

	assert.Contains(t, client.pipeliner.capturedKeys[2], "session_login")
	assert.Contains(t, client.pipeliner.capturedKeys[2], "sess-abc123")

	// F1: Verify Expire keys match Incr keys for all dimensions
	require.Len(t, client.pipeliner.capturedExpireKeys, 3)
	for i := 0; i < 3; i++ {
		assert.Equal(t, client.pipeliner.capturedKeys[i], client.pipeliner.capturedExpireKeys[i], "Expire key must match Incr key for dimension %d", i)
	}
}

func TestMultiCheckLimiter_Check_Remaining_MinimumAcrossDimensions(t *testing.T) {
	// AC5: Remaining reflects minimum across all dimensions
	// Distinct from AllUnderLimit: pre-set counter to 2 so counts are 3,4,5
	// with limits 100,6,50 → remaining 97,2,45 → min=2
	client := newTestMultiCheckClient()
	atomic.StoreInt64(&client.counter, 2)
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 100, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 6, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 50, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 2, result.Remaining, "Remaining should be min across all dimensions (email: 6-4=2)")
}

func TestMultiCheckLimiter_Check_FirstBlockedDimensionWins(t *testing.T) {
	// AC3 edge case: multiple blocked dims → first in slice order is reported
	client := newTestMultiCheckClient()
	// Set counter high so both email (limit=5) and session (limit=3) exceed
	// Counter: ip=10, email=11, session=12. ip limit=30 ok, email limit=5 blocked, session limit=3 blocked
	atomic.StoreInt64(&client.counter, 9)
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 3, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "email", result.BlockedBy, "first blocked dimension in slice order should be reported")
}

func TestMultiCheckLimiter_Check_SingleDimension(t *testing.T) {
	// Edge case: single dimension works correctly
	client := newTestMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 29, result.Remaining) // 30 - 1 = 29
}

func TestNewMultiCheckLimiter_PanicsOnNilClient(t *testing.T) {
	require.Panics(t, func() {
		NewMultiCheckLimiter(nil, testNopLogger())
	})
}

func TestNewMultiCheckLimiter_PanicsOnNilLogger(t *testing.T) {
	require.Panics(t, func() {
		NewMultiCheckLimiter(newTestMultiCheckClient(), nil)
	})
}

func TestMultiCheckLimiter_Check_PipelineExecRedisNil_Succeeds(t *testing.T) {
	// Pipeline Exec returns redis.Nil → treated as success, not error (line 104 explicitly filters redis.Nil)
	client := newTestMultiCheckClient()
	client.pipeExecErr = redis.Nil
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestMultiCheckLimiter_Check_EmptyKeyDimension_Skipped(t *testing.T) {
	// Security fix H3: empty key dimensions are skipped to prevent shared global bucket
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "", Action: "login", Limit: 30, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed, "empty key dimension should be skipped, returning Allowed=true")
	assert.Len(t, client.pipeliner.capturedKeys, 0, "empty key should not produce Redis calls")
}

func TestMultiCheckLimiter_Check_EmptyKeyDimension_MixedWithValid(t *testing.T) {
	// Security fix H3: empty key dimension is skipped but valid dimensions still checked
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "", Action: "login", Limit: 5, Window: time.Minute}, // skipped
		{Prefix: "session", Key: "sess-abc", Action: "login", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 2, "only non-empty key dimensions should be sent to Redis")
	for _, key := range client.pipeliner.capturedKeys {
		assert.NotContains(t, key, "email", "empty-key email dimension should be skipped")
	}
}

func TestMultiCheckLimiter_Check_EmptyPrefixDimension_Skipped(t *testing.T) {
	// Adversarial F2: empty Prefix dimensions should be skipped
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc", Action: "login", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 1, "empty-prefix dimension should be skipped")
	assert.Contains(t, client.pipeliner.capturedKeys[0], "session_login")
}

func TestMultiCheckLimiter_Check_EmptyActionDimension_Skipped(t *testing.T) {
	// Adversarial F2: empty Action dimensions should be skipped
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "", Limit: 30, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc", Action: "login", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 1, "empty-action dimension should be skipped")
	assert.Contains(t, client.pipeliner.capturedKeys[0], "session_login")
}

func TestMultiCheckLimiter_Check_KeyFormat_SanitizesPrefixAndAction(t *testing.T) {
	// Verify sanitizeKeySegment is applied to Prefix and Action (review fix F2)
	// Colons in Prefix or Action must be escaped to prevent Redis key injection
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "api:auth", Key: "user1", Action: "login:step2", Limit: 10, Window: time.Minute},
	}

	_, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	require.Len(t, client.pipeliner.capturedKeys, 1)

	key := client.pipeliner.capturedKeys[0]
	// Prefix "api:auth" → "api%3Aauth", Action "login:step2" → "login%3Astep2"
	assert.Contains(t, key, "api%3Aauth_login%3Astep2", "colons in Prefix and Action should be escaped via sanitizeKeySegment")
	assert.NotContains(t, key, "api:auth", "raw colons in Prefix should not appear in Redis key")
	assert.NotContains(t, key, "login:step2", "raw colons in Action should not appear in Redis key")
}

func TestMultiCheckLimiter_Check_NilDimensions(t *testing.T) {
	// Nil slice should behave identically to empty slice → Allowed=true, no Redis calls
	client := newCaptureMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	result, err := limiter.Check(context.Background(), nil)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Len(t, client.pipeliner.capturedKeys, 0, "no Redis calls for nil dimensions")
}

func TestMultiCheckLimiter_Check_PerCommandIncrError_FailClosed(t *testing.T) {
	// Security fix H2: per-command INCR error should fail closed (return ErrInfrastructure)
	client := &errorIncrClient{
		RedisClient: redisclient.NewMockRedisClient(),
		pipeliner:   &errorIncrPipeliner{incrErr: errRedis},
	}
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.Error(t, err)
	assert.Nil(t, result)
	var infraErr *ErrInfrastructure
	assert.True(t, errors.As(err, &infraErr), "per-command INCR error should be wrapped in ErrInfrastructure")
}

func TestMultiCheckLimiter_Check_PartialIncrError_FailClosed(t *testing.T) {
	// Adversarial F4: first dimension succeeds, second fails → should still fail closed
	client := &partialErrorClient{
		RedisClient: redisclient.NewMockRedisClient(),
		pipeliner:   &partialErrorPipeliner{successCount: 1, incrErr: errRedis},
	}
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.Error(t, err)
	assert.Nil(t, result)
	var infraErr *ErrInfrastructure
	assert.True(t, errors.As(err, &infraErr), "partial INCR error should be wrapped in ErrInfrastructure")
}

func TestMultiCheckLimiter_Check_BlockedResult_IncludesLimit(t *testing.T) {
	// When blocked, verify result.Limit equals the blocking dimension's limit
	client := newTestMultiCheckClient()
	atomic.StoreInt64(&client.counter, 5) // next INCR → 6, exceeds limit=5
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, 5, result.Limit, "result.Limit should equal the blocking dimension's limit")
	assert.Equal(t, "email", result.BlockedBy)
}

func TestMultiCheckLimiter_Check_BlockedBy_ReturnsRawPrefix(t *testing.T) {
	// Adversarial F10: BlockedBy should return the raw unsanitized Prefix
	client := newTestMultiCheckClient()
	atomic.StoreInt64(&client.counter, 10) // next INCR → 11, exceeds limit=10
	limiter := NewMultiCheckLimiter(client, testNopLogger())

	dims := []CheckDimension{
		{Prefix: "api:auth", Key: "user1", Action: "login:step2", Limit: 10, Window: time.Minute},
	}

	result, err := limiter.Check(context.Background(), dims)

	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, "api:auth", result.BlockedBy, "BlockedBy should return raw Prefix, not sanitized")
}
