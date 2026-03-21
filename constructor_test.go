package ratelimiter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	redisclient "github.com/turnkeystaffing/go-redis"
)

// --- NewRedisRateLimiter nil-check tests ---

func TestNewRedisRateLimiter_NilClient_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewRedisRateLimiter: client cannot be nil", func() {
		NewRedisRateLimiter(nil, testNopLogger())
	})
}

func TestNewRedisRateLimiter_NilLogger_Panics(t *testing.T) {
	client := redisclient.NewMockRedisClient()
	assert.PanicsWithValue(t, "NewRedisRateLimiter: logger cannot be nil", func() {
		NewRedisRateLimiter(client, nil)
	})
}

// --- NewDualLayerRateLimiter nil-check tests ---

func TestNewDualLayerRateLimiter_NilBaseLimiter_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDualLayerRateLimiter: baseLimiter cannot be nil", func() {
		NewDualLayerRateLimiter(nil, &DualLayerConfig{}, "oauth", testNopLogger())
	})
}

func TestNewDualLayerRateLimiter_NilConfig_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDualLayerRateLimiter: config cannot be nil", func() {
		NewDualLayerRateLimiter(NewRateLimiter(), nil, "oauth", testNopLogger())
	})
}

func TestNewDualLayerRateLimiter_NilLogger_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDualLayerRateLimiter: logger cannot be nil", func() {
		NewDualLayerRateLimiter(NewRateLimiter(), &DualLayerConfig{}, "oauth", nil)
	})
}

// --- NewFallbackRateLimiter nil-check tests ---

func TestNewFallbackRateLimiter_NilPrimary_Panics(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, time.Hour, testNopLogger())
	defer monitor.Stop()
	assert.PanicsWithValue(t, "NewFallbackRateLimiter: primary cannot be nil", func() {
		NewFallbackRateLimiter(nil, NewRateLimiter(), monitor, testNopLogger(), 3)
	})
}

func TestNewFallbackRateLimiter_NilFallback_Panics(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, time.Hour, testNopLogger())
	defer monitor.Stop()
	assert.PanicsWithValue(t, "NewFallbackRateLimiter: fallback cannot be nil", func() {
		NewFallbackRateLimiter(NewRateLimiter(), nil, monitor, testNopLogger(), 3)
	})
}

func TestNewFallbackRateLimiter_NilMonitor_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewFallbackRateLimiter: monitor cannot be nil", func() {
		NewFallbackRateLimiter(NewRateLimiter(), NewRateLimiter(), nil, testNopLogger(), 3)
	})
}

func TestNewFallbackRateLimiter_NilLogger_Panics(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, time.Hour, testNopLogger())
	defer monitor.Stop()
	assert.PanicsWithValue(t, "NewFallbackRateLimiter: logger cannot be nil", func() {
		NewFallbackRateLimiter(NewRateLimiter(), NewRateLimiter(), monitor, nil, 3)
	})
}

// --- NewDegradationMonitor nil-check tests ---

func TestNewDegradationMonitor_NilRecoveryCheck_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDegradationMonitor: recoveryCheck cannot be nil", func() {
		NewDegradationMonitor(nil, time.Second, testNopLogger())
	})
}

func TestNewDegradationMonitor_ZeroInterval_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDegradationMonitor: interval must be positive", func() {
		NewDegradationMonitor(func() bool { return true }, 0, testNopLogger())
	})
}

func TestNewDegradationMonitor_NilLogger_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDegradationMonitor: logger cannot be nil", func() {
		NewDegradationMonitor(func() bool { return true }, time.Second, nil)
	})
}

func TestNewFallbackRateLimiter_DefaultThreshold(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, time.Hour, testNopLogger())
	defer monitor.Stop()
	// Zero threshold should default to 1
	fb := NewFallbackRateLimiter(NewRateLimiter(), NewRateLimiter(), monitor, testNopLogger(), 0)
	assert.NotNil(t, fb)
}
