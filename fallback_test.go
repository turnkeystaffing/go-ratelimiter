package ratelimiter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLimiter is a minimal RateLimiterInterface mock for fallback tests.
type mockLimiter struct {
	checkErr  error
	checkCall int32
}

func (m *mockLimiter) CheckRateLimit(_ context.Context, _ string, _ string, _ int, _ time.Duration) error {
	atomic.AddInt32(&m.checkCall, 1)
	return m.checkErr
}

func (m *mockLimiter) GetBucketStatus(_ context.Context, _ string, _ string) (int, int, time.Time) {
	return 0, 0, time.Time{}
}

func (m *mockLimiter) calls() int32 {
	return atomic.LoadInt32(&m.checkCall)
}

// mockMonitor is a minimal pkgredis.DegradationMonitor for tests.
type mockMonitor struct {
	degraded atomic.Bool
}

func (m *mockMonitor) IsDegraded() bool { return m.degraded.Load() }
func (m *mockMonitor) MarkDegraded()    { m.degraded.Store(true) }
func (m *mockMonitor) MarkHealthy()     { m.degraded.Store(false) }

func newAlwaysHealthyMonitor() *mockMonitor {
	return &mockMonitor{}
}

func TestFallbackRateLimiter_PrimaryReturnsRateLimited(t *testing.T) {
	primary := &mockLimiter{checkErr: &ErrRateLimited{RetryAfter: 30 * time.Second, Limit: 10}}
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)

	// Should return the rate limit error directly, not fall back
	require.Error(t, err)
	var rateLimited *ErrRateLimited
	require.True(t, errors.As(err, &rateLimited))
	assert.Equal(t, 10, rateLimited.Limit)
	assert.Equal(t, 30*time.Second, rateLimited.RetryAfter)

	// Fallback should NOT have been called
	assert.Equal(t, int32(0), fallback.calls())
	// Monitor should NOT be degraded
	assert.False(t, monitor.IsDegraded())
}

func TestFallbackRateLimiter_PrimaryReturnsInfrastructureError(t *testing.T) {
	primary := &mockLimiter{checkErr: &ErrInfrastructure{Cause: errRedis}}
	fallback := &mockLimiter{} // returns nil
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)

	// Should succeed via fallback
	assert.NoError(t, err)
	// Fallback should have been called
	assert.Equal(t, int32(1), fallback.calls())
	// Monitor should be degraded (threshold=1, single failure triggers)
	assert.True(t, monitor.IsDegraded())
}

func TestFallbackRateLimiter_PrimaryReturnsGenericError(t *testing.T) {
	primary := &mockLimiter{checkErr: errors.New("connection timeout")}
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)

	assert.NoError(t, err)
	assert.Equal(t, int32(1), fallback.calls())
	assert.True(t, monitor.IsDegraded())
}

func TestFallbackRateLimiter_DegradedModeSkipsPrimary(t *testing.T) {
	primary := &mockLimiter{checkErr: &ErrInfrastructure{Cause: errRedis}}
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()

	monitor.MarkDegraded()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)

	assert.NoError(t, err)
	// Primary should NOT have been called
	assert.Equal(t, int32(0), primary.calls())
	// Fallback should have been called
	assert.Equal(t, int32(1), fallback.calls())
}

func TestFallbackRateLimiter_RecoveryRestoresPrimary(t *testing.T) {
	primary := &mockLimiter{} // returns nil (healthy)
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()
	monitor.MarkDegraded()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	// While degraded, fallback is used
	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)
	assert.NoError(t, err)
	assert.Equal(t, int32(0), primary.calls())
	assert.Equal(t, int32(1), fallback.calls())

	// Simulate recovery (e.g., go-redis HealthMonitor probe succeeds)
	monitor.MarkHealthy()
	assert.False(t, monitor.IsDegraded())

	// Now primary should be used again
	err = fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)
	assert.NoError(t, err)
	assert.Equal(t, int32(1), primary.calls())
}

func TestFallbackRateLimiter_FallbackReturnsRateLimited(t *testing.T) {
	primary := &mockLimiter{checkErr: &ErrInfrastructure{Cause: errRedis}}
	fallback := &mockLimiter{checkErr: &ErrRateLimited{RetryAfter: 10 * time.Second, Limit: 5}}
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 5, time.Minute)

	require.Error(t, err)
	var rateLimited *ErrRateLimited
	require.True(t, errors.As(err, &rateLimited))
	assert.Equal(t, 5, rateLimited.Limit)
}

func TestFallbackRateLimiter_PrimarySuccess(t *testing.T) {
	primary := &mockLimiter{} // nil error = success
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)

	assert.NoError(t, err)
	assert.Equal(t, int32(1), primary.calls())
	assert.Equal(t, int32(0), fallback.calls())
	assert.False(t, monitor.IsDegraded())
}

func TestFallbackRateLimiter_GetBucketStatus_Delegation(t *testing.T) {
	now := time.Now()
	primary := &statusMockLimiter{count: 5, max: 10, resetAt: now}
	fallback := &statusMockLimiter{count: 2, max: 10, resetAt: now.Add(time.Minute)}
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 1)

	// Healthy: delegates to primary — should see primary's values
	count, max, ts := fb.GetBucketStatus(context.Background(), "user-1", "login")
	assert.Equal(t, 5, count)
	assert.Equal(t, 10, max)
	assert.Equal(t, now, ts)

	// Degraded: delegates to fallback — should see fallback's values
	monitor.MarkDegraded()
	count, max, ts = fb.GetBucketStatus(context.Background(), "user-1", "login")
	assert.Equal(t, 2, count)
	assert.Equal(t, 10, max)
	assert.Equal(t, now.Add(time.Minute), ts)
}

// --- Failure Threshold Tests ---

func TestFallbackRateLimiter_ThresholdRequiresConsecutiveFailures(t *testing.T) {
	callCount := int32(0)
	primary := &mockLimiter{checkErr: &ErrInfrastructure{Cause: errRedis}}
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()

	// Threshold of 3: need 3 consecutive failures to degrade
	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 3)

	// First failure: should use fallback but NOT mark degraded
	err := fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)
	assert.NoError(t, err)
	assert.False(t, monitor.IsDegraded(), "should not degrade after 1 failure with threshold=3")
	callCount = fallback.calls()
	assert.Equal(t, int32(1), callCount)

	// Second failure: still not degraded
	err = fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)
	assert.NoError(t, err)
	assert.False(t, monitor.IsDegraded(), "should not degrade after 2 failures with threshold=3")

	// Third failure: NOW should degrade
	err = fb.CheckRateLimit(context.Background(), "user-1", "login", 10, time.Minute)
	assert.NoError(t, err)
	assert.True(t, monitor.IsDegraded(), "should degrade after 3 consecutive failures with threshold=3")
}

func TestFallbackRateLimiter_SuccessResetsFailureCount(t *testing.T) {
	failureCount := atomic.Int32{}
	failureCount.Store(0)

	primary := &countingMockLimiter{
		responses: []error{
			&ErrInfrastructure{Cause: errRedis}, // failure 1
			&ErrInfrastructure{Cause: errRedis}, // failure 2
			nil,                                 // success — resets counter
			&ErrInfrastructure{Cause: errRedis}, // failure 1 again
			&ErrInfrastructure{Cause: errRedis}, // failure 2 again
		},
	}
	fallback := &mockLimiter{}
	monitor := newAlwaysHealthyMonitor()

	fb := NewFallbackRateLimiter(primary, fallback, monitor, testNopLogger(), 3)

	// 2 failures
	fb.CheckRateLimit(context.Background(), "u", "a", 10, time.Minute)
	fb.CheckRateLimit(context.Background(), "u", "a", 10, time.Minute)
	assert.False(t, monitor.IsDegraded())

	// 1 success — resets counter
	fb.CheckRateLimit(context.Background(), "u", "a", 10, time.Minute)
	assert.False(t, monitor.IsDegraded())

	// 2 more failures — counter started fresh, threshold not reached
	fb.CheckRateLimit(context.Background(), "u", "a", 10, time.Minute)
	fb.CheckRateLimit(context.Background(), "u", "a", 10, time.Minute)
	assert.False(t, monitor.IsDegraded(), "success should have reset the failure counter")
}

// statusMockLimiter returns configurable GetBucketStatus values.
type statusMockLimiter struct {
	count   int
	max     int
	resetAt time.Time
}

func (m *statusMockLimiter) CheckRateLimit(_ context.Context, _ string, _ string, _ int, _ time.Duration) error {
	return nil
}

func (m *statusMockLimiter) GetBucketStatus(_ context.Context, _ string, _ string) (int, int, time.Time) {
	return m.count, m.max, m.resetAt
}

// countingMockLimiter returns errors in sequence.
type countingMockLimiter struct {
	responses []error
	idx       int32
}

func (m *countingMockLimiter) CheckRateLimit(_ context.Context, _ string, _ string, _ int, _ time.Duration) error {
	i := atomic.AddInt32(&m.idx, 1) - 1
	if int(i) < len(m.responses) {
		return m.responses[i]
	}
	return nil
}

func (m *countingMockLimiter) GetBucketStatus(_ context.Context, _ string, _ string) (int, int, time.Time) {
	return 0, 0, time.Time{}
}
