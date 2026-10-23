package ratelimiter

import (
	"context"
	"testing"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCooldownClient is a mock RedisClient with configurable SetNX() and TTL() for CooldownChecker tests.
type testCooldownClient struct {
	redisclient.RedisClient // embed for unused methods (delegates to MockRedisClient)
	setNXResult             bool
	setNXErr                error
	ttlResult               time.Duration
	ttlErr                  error
}

func newTestCooldownClient() *testCooldownClient {
	return &testCooldownClient{
		RedisClient: redisclient.NewMockRedisClient(),
		setNXResult: true, // default: action allowed (key was set)
	}
}

func (c *testCooldownClient) SetNX(_ context.Context, _ string, _ interface{}, _ time.Duration) (bool, error) {
	if c.setNXErr != nil {
		return false, c.setNXErr
	}
	return c.setNXResult, nil
}

func (c *testCooldownClient) TTL(_ context.Context, _ string) (time.Duration, error) {
	if c.ttlErr != nil {
		return 0, c.ttlErr
	}
	return c.ttlResult, nil
}

// captureKeyClient captures the Redis key and expiration passed to SetNX,
// and the key passed to TTL, for assertions.
type captureKeyClient struct {
	testCooldownClient
	capturedKey        string
	capturedExpiration time.Duration
	capturedTTLKey     string
}

func (c *captureKeyClient) SetNX(_ context.Context, key string, _ interface{}, expiration time.Duration) (bool, error) {
	c.capturedKey = key
	c.capturedExpiration = expiration
	if c.setNXErr != nil {
		return false, c.setNXErr
	}
	return c.setNXResult, nil
}

func (c *captureKeyClient) TTL(_ context.Context, key string) (time.Duration, error) {
	c.capturedTTLKey = key
	if c.ttlErr != nil {
		return 0, c.ttlErr
	}
	return c.ttlResult, nil
}

// --- CheckAndSet tests ---

func TestCooldownChecker_CheckAndSet_NotBlocked_FirstCall(t *testing.T) {
	// AC2 + AC4: SetNX returns true → no cooldown active, action allowed
	client := newTestCooldownClient() // setNXResult defaults to true

	checker := NewCooldownChecker(client, testNopLogger())

	result, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", 60*time.Second)

	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Zero(t, result.RetryAfter, "RetryAfter should be zero when not blocked")
}

func TestCooldownChecker_CheckAndSet_Blocked_CooldownActive(t *testing.T) {
	// AC3: SetNX returns false (key exists), TTL returns 30s → blocked
	client := newTestCooldownClient()
	client.setNXResult = false
	client.ttlResult = 30 * time.Second

	checker := NewCooldownChecker(client, testNopLogger())

	result, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", 60*time.Second)

	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, 30*time.Second, result.RetryAfter)
}

func TestCooldownChecker_CheckAndSet_FailClosed_SetNXRedisError(t *testing.T) {
	// AC5: Redis unavailable on SetNX → fail-closed (error returned)
	client := newTestCooldownClient()
	client.setNXErr = errRedis

	checker := NewCooldownChecker(client, testNopLogger())

	result, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", 60*time.Second)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, errRedis)
}

func TestCooldownChecker_CheckAndSet_Blocked_TTLError_FallbackToFullCooldown(t *testing.T) {
	// AC6: SetNX returns false, TTL errors → blocked with full cooldown as RetryAfter
	client := newTestCooldownClient()
	client.setNXResult = false
	client.ttlErr = errRedis

	checker := NewCooldownChecker(client, testNopLogger())

	cooldown := 120 * time.Second
	result, err := checker.CheckAndSet(context.Background(), "user-123", "2fa_resend", cooldown)

	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, cooldown, result.RetryAfter)
}

func TestCooldownChecker_CheckAndSet_Blocked_TTLNonPositive_FallbackToFullCooldown(t *testing.T) {
	// AC7: SetNX returns false, TTL returns -1 → blocked with full cooldown as RetryAfter
	client := newTestCooldownClient()
	client.setNXResult = false
	client.ttlResult = -1 * time.Second

	checker := NewCooldownChecker(client, testNopLogger())

	cooldown := 90 * time.Second
	result, err := checker.CheckAndSet(context.Background(), "user-123", "email_send", cooldown)

	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, cooldown, result.RetryAfter)
}

func TestCooldownChecker_CheckAndSet_KeyFormat(t *testing.T) {
	// AC8: Key format is rate_limit:{sanitized}:cd_{action}:cooldown
	client := &captureKeyClient{
		testCooldownClient: *newTestCooldownClient(), // setNXResult defaults to true
	}

	checker := NewCooldownChecker(client, testNopLogger())

	_, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", 60*time.Second)

	require.NoError(t, err)
	assert.Equal(t, "rate_limit:user-123:cd_password_change:cooldown", client.capturedKey)
	assert.NotContains(t, client.capturedKey, "auth_", "key should not contain auth_ prefix")
}

func TestCooldownChecker_CheckAndSet_KeyFormat_SanitizesColons(t *testing.T) {
	// AC9: Colons in key segment are escaped via sanitizeKeySegment()
	client := &captureKeyClient{
		testCooldownClient: *newTestCooldownClient(), // setNXResult defaults to true
	}

	checker := NewCooldownChecker(client, testNopLogger())

	_, err := checker.CheckAndSet(context.Background(), "::1", "password_change", 60*time.Second)

	require.NoError(t, err)
	assert.Equal(t, "rate_limit:%3A%3A1:cd_password_change:cooldown", client.capturedKey)
	assert.NotContains(t, client.capturedKey, ":::", "raw colons should not appear in key segment")
}

func TestCooldownChecker_CheckAndSet_KeyFormat_EmptyKey(t *testing.T) {
	// Edge case: empty key produces empty segment in Redis key
	client := &captureKeyClient{
		testCooldownClient: *newTestCooldownClient(),
	}

	checker := NewCooldownChecker(client, testNopLogger())

	_, err := checker.CheckAndSet(context.Background(), "", "password_change", 60*time.Second)

	require.NoError(t, err)
	assert.Equal(t, "rate_limit::cd_password_change:cooldown", client.capturedKey)
}

func TestCooldownChecker_CheckAndSet_KeyFormat_EmptyAction(t *testing.T) {
	// Edge case: empty action produces cd_ with no suffix
	client := &captureKeyClient{
		testCooldownClient: *newTestCooldownClient(),
	}

	checker := NewCooldownChecker(client, testNopLogger())

	_, err := checker.CheckAndSet(context.Background(), "user-123", "", 60*time.Second)

	require.NoError(t, err)
	assert.Equal(t, "rate_limit:user-123:cd_:cooldown", client.capturedKey)
}

func TestCooldownChecker_CheckAndSet_ForwardsCooldownDurationToRedis(t *testing.T) {
	// Verify the cooldown parameter is correctly forwarded as the SetNX expiration
	client := &captureKeyClient{
		testCooldownClient: *newTestCooldownClient(), // setNXResult defaults to true
	}

	checker := NewCooldownChecker(client, testNopLogger())

	cooldown := 90 * time.Second
	_, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", cooldown)

	require.NoError(t, err)
	assert.Equal(t, cooldown, client.capturedExpiration, "cooldown duration should be forwarded to SetNX as expiration")
}

func TestCooldownChecker_CheckAndSet_Blocked_TTLZero_FallbackToFullCooldown(t *testing.T) {
	// Boundary: TTL returns 0 (non-positive) → fallback to full cooldown
	client := newTestCooldownClient()
	client.setNXResult = false
	client.ttlResult = 0

	checker := NewCooldownChecker(client, testNopLogger())

	cooldown := 60 * time.Second
	result, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", cooldown)

	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, cooldown, result.RetryAfter, "TTL=0 should fallback to full cooldown")
}

func TestCooldownChecker_CheckAndSet_ZeroDurationCooldown_ReturnsError(t *testing.T) {
	// Security fix S1: zero cooldown would create permanent Redis key (no TTL).
	// Library now rejects zero duration to prevent permanent lockout.
	client := newTestCooldownClient()

	checker := NewCooldownChecker(client, testNopLogger())

	result, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", 0)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidCooldown)
}

func TestCooldownChecker_CheckAndSet_NegativeDurationCooldown_ReturnsError(t *testing.T) {
	// Security fix S1/S4: negative cooldown causes Redis SET error (negative EX rejected).
	// Library now rejects negative duration at the API boundary.
	client := newTestCooldownClient()

	checker := NewCooldownChecker(client, testNopLogger())

	result, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", -5*time.Second)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidCooldown)
}

func TestCooldownChecker_CheckAndSet_TTLUseSameKeyAsSetNX(t *testing.T) {
	// F3: Verify TTL receives the same Redis key as SetNX when cooldown is active
	client := &captureKeyClient{
		testCooldownClient: *newTestCooldownClient(),
	}
	client.setNXResult = false
	client.ttlResult = 30 * time.Second

	checker := NewCooldownChecker(client, testNopLogger())

	_, err := checker.CheckAndSet(context.Background(), "user-123", "password_change", 60*time.Second)

	require.NoError(t, err)
	assert.Equal(t, client.capturedKey, client.capturedTTLKey, "TTL must use the same Redis key as SetNX")
	assert.Equal(t, "rate_limit:user-123:cd_password_change:cooldown", client.capturedTTLKey)
}

func TestCooldownChecker_CheckAndSet_FailClosed_CancelledContext(t *testing.T) {
	// F4: Cancelled context produces fail-closed error
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := newTestCooldownClient()
	client.setNXErr = ctx.Err() // simulate Redis returning context error

	checker := NewCooldownChecker(client, testNopLogger())

	result, err := checker.CheckAndSet(ctx, "user-123", "password_change", 60*time.Second)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, context.Canceled)
}

// --- Constructor nil-check tests ---

func TestNewCooldownChecker_PanicsOnNilClient(t *testing.T) {
	require.Panics(t, func() {
		NewCooldownChecker(nil, testNopLogger())
	})
}

func TestNewCooldownChecker_PanicsOnNilLogger(t *testing.T) {
	require.Panics(t, func() {
		NewCooldownChecker(newTestCooldownClient(), nil)
	})
}

// setDelClient records the Set and Del calls made by CooldownChecker.Set and Release.
type setDelClient struct {
	testCooldownClient
	setKey        string
	setExpiration time.Duration
	setErr        error
	delKeys       []string
	delErr        error
}

func (c *setDelClient) Set(_ context.Context, key string, _ interface{}, expiration time.Duration) error {
	c.setKey = key
	c.setExpiration = expiration
	return c.setErr
}

func (c *setDelClient) Del(_ context.Context, keys ...string) (int64, error) {
	c.delKeys = append(c.delKeys, keys...)
	if c.delErr != nil {
		return 0, c.delErr
	}
	return int64(len(keys)), nil
}

// --- Set tests ---

func TestCooldownChecker_Set_WritesUnconditionallyWithCooldownTTL(t *testing.T) {
	// Set must overwrite (plain SET EX, no NX) so an action can restart an active window;
	// it must hit the same key CheckAndSet reads, or the restart would be invisible to it.
	client := &setDelClient{testCooldownClient: *newTestCooldownClient()}
	checker := NewCooldownChecker(client, testNopLogger())

	err := checker.Set(context.Background(), "user:123", "2fa_setup_login_email", 15*time.Minute)

	require.NoError(t, err)
	assert.Equal(t, "rate_limit:user%3A123:cd_2fa_setup_login_email:cooldown", client.setKey)
	assert.Equal(t, 15*time.Minute, client.setExpiration)
}

func TestCooldownChecker_Set_RedisError_Returned(t *testing.T) {
	client := &setDelClient{testCooldownClient: *newTestCooldownClient(), setErr: assert.AnError}
	checker := NewCooldownChecker(client, testNopLogger())

	err := checker.Set(context.Background(), "user-123", "action", time.Minute)

	assert.ErrorIs(t, err, assert.AnError)
}

func TestCooldownChecker_Set_NonPositiveCooldown_ReturnsError(t *testing.T) {
	client := &setDelClient{testCooldownClient: *newTestCooldownClient()}
	checker := NewCooldownChecker(client, testNopLogger())

	assert.ErrorIs(t, checker.Set(context.Background(), "user-123", "action", 0), ErrInvalidCooldown)
	assert.ErrorIs(t, checker.Set(context.Background(), "user-123", "action", -time.Second), ErrInvalidCooldown)
	assert.Empty(t, client.setKey, "nothing may be written for an invalid cooldown")
}

// --- Release tests ---

func TestCooldownChecker_Release_DeletesTheCheckAndSetKey(t *testing.T) {
	// Release must free exactly the key CheckAndSet and Set use, so a failed action
	// doesn't leave the identity blocked for the whole window.
	client := &setDelClient{testCooldownClient: *newTestCooldownClient()}
	checker := NewCooldownChecker(client, testNopLogger())

	err := checker.Release(context.Background(), "user:123", "2fa_setup_login_email")

	require.NoError(t, err)
	assert.Equal(t, []string{"rate_limit:user%3A123:cd_2fa_setup_login_email:cooldown"}, client.delKeys)
}

func TestCooldownChecker_Release_RedisError_Returned(t *testing.T) {
	client := &setDelClient{testCooldownClient: *newTestCooldownClient(), delErr: assert.AnError}
	checker := NewCooldownChecker(client, testNopLogger())

	assert.ErrorIs(t, checker.Release(context.Background(), "user-123", "action"), assert.AnError)
}
