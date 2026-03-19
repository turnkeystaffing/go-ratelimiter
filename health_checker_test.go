package ratelimiter

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/turnkeystaffing/go-health"
)

func serviceTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stubDegradationDetector implements degradationDetector for testing.
type stubDegradationDetector struct {
	degraded bool
}

func (s *stubDegradationDetector) IsDegraded() bool {
	return s.degraded
}

func TestRateLimiterHealthChecker_Healthy(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: false}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	result := checker.Check(context.Background())
	assert.Equal(t, health.CheckPass, result.Status)
	assert.Equal(t, "rate_limiter", result.Name)
	assert.Empty(t, result.Error)
}

func TestRateLimiterHealthChecker_Degraded(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: true}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	result := checker.Check(context.Background())
	assert.Equal(t, health.CheckWarn, result.Status)
	assert.Contains(t, result.Error, "degraded")
}

func TestRateLimiterHealthChecker_TransitionHealthyToDegraded(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: false}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	// Start healthy
	result := checker.Check(context.Background())
	assert.Equal(t, health.CheckPass, result.Status)

	// Transition to degraded
	detector.degraded = true
	result = checker.Check(context.Background())
	assert.Equal(t, health.CheckWarn, result.Status)
	assert.True(t, checker.wasDegraded.Load())
}

func TestRateLimiterHealthChecker_TransitionDegradedToHealthy(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: true}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	// Start degraded
	result := checker.Check(context.Background())
	assert.Equal(t, health.CheckWarn, result.Status)
	assert.True(t, checker.wasDegraded.Load())

	// Transition to healthy (recovery)
	detector.degraded = false
	result = checker.Check(context.Background())
	assert.Equal(t, health.CheckPass, result.Status)
	assert.False(t, checker.wasDegraded.Load())
}

func TestRateLimiterHealthChecker_RepeatedDegradedNoRetrigger(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: true}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	checker.Check(context.Background())
	assert.True(t, checker.wasDegraded.Load())

	checker.Check(context.Background())
	assert.True(t, checker.wasDegraded.Load(), "should remain degraded without retriggering")
}

func TestRateLimiterHealthChecker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: false}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result := checker.Check(context.Background())
			assert.Equal(t, health.CheckPass, result.Status)
		}()
	}
	wg.Wait()
}

func TestRateLimiterHealthChecker_DurationTracked(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: false}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	result := checker.Check(context.Background())
	assert.GreaterOrEqual(t, result.Duration.Nanoseconds(), int64(0))
	assert.NotZero(t, result.Timestamp)
}

func TestNewRateLimiterHealthChecker_PanicsOnNilLimiter(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "NewRateLimiterHealthChecker: limiter cannot be nil", func() {
		NewRateLimiterHealthChecker(nil, serviceTestLogger())
	})
}

func TestNewRateLimiterHealthChecker_PanicsOnNilLogger(t *testing.T) {
	t.Parallel()
	detector := &stubDegradationDetector{}
	assert.PanicsWithValue(t, "NewRateLimiterHealthChecker: logger cannot be nil", func() {
		NewRateLimiterHealthChecker(detector, nil)
	})
}

func TestRateLimiterHealthChecker_MultiCycleTransitions(t *testing.T) {
	t.Parallel()

	detector := &stubDegradationDetector{degraded: false}
	checker := NewRateLimiterHealthChecker(detector, serviceTestLogger())

	// Cycle 1: healthy → degraded
	result := checker.Check(context.Background())
	assert.Equal(t, health.CheckPass, result.Status)

	detector.degraded = true
	result = checker.Check(context.Background())
	assert.Equal(t, health.CheckWarn, result.Status)
	assert.True(t, checker.wasDegraded.Load())

	// Cycle 2: degraded → healthy (recovery)
	detector.degraded = false
	result = checker.Check(context.Background())
	assert.Equal(t, health.CheckPass, result.Status)
	assert.False(t, checker.wasDegraded.Load())

	// Cycle 3: healthy → degraded again
	detector.degraded = true
	result = checker.Check(context.Background())
	assert.Equal(t, health.CheckWarn, result.Status)
	assert.True(t, checker.wasDegraded.Load())
}

func TestRateLimiterHealthChecker_NonDetectorLimiter_AlwaysHealthy(t *testing.T) {
	t.Parallel()

	// Pass a limiter that does NOT implement degradationDetector
	limiter := NewNoopRateLimiter()
	checker := NewRateLimiterHealthChecker(limiter, serviceTestLogger())

	result := checker.Check(context.Background())
	assert.Equal(t, health.CheckPass, result.Status)
}
