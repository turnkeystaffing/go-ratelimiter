package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFailureTracker implements FailureTrackerInterface for Guard[T] unit tests.
// This validates AC10: FailureTrackerInterface enables mock injection.
type mockFailureTracker struct {
	isBlockedResult *FailureCheckResult
	isBlockedErr    error
	recordErr       error
	recordCalled    bool
}

func (m *mockFailureTracker) IsBlocked(_ context.Context, _ FailureConfig) (*FailureCheckResult, error) {
	if m.isBlockedErr != nil {
		return nil, m.isBlockedErr
	}
	return m.isBlockedResult, nil
}

func (m *mockFailureTracker) RecordFailure(_ context.Context, _ FailureConfig) error {
	m.recordCalled = true
	return m.recordErr
}

// --- Guard[T] tests ---

func TestGuard_Success_NoFailureRecorded(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 10},
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	called := false
	val, err := Guard(guard, context.Background(), "client-123", func() (string, error) {
		called = true
		return "success-value", nil
	})

	require.NoError(t, err)
	assert.True(t, called, "expected fn to be called")
	assert.Equal(t, "success-value", val)
	assert.False(t, mock.recordCalled, "RecordFailure should NOT be called on success")
}

func TestGuard_FnError_RecordsFailure(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 10},
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	fnErr := fmt.Errorf("authentication failed")
	val, err := Guard(guard, context.Background(), "client-123", func() (string, error) {
		return "", fnErr
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, fnErr), "expected original fn error")
	assert.Equal(t, "", val, "expected zero value on error")
	assert.True(t, mock.recordCalled, "RecordFailure should be called on fn error")
}

func TestGuard_FnError_PreservesPartialValue(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 10},
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	fnErr := fmt.Errorf("partial failure")
	val, err := Guard(guard, context.Background(), "client-123", func() (string, error) {
		return "partial-data", fnErr
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, fnErr), "expected original fn error")
	assert.Equal(t, "partial-data", val, "Guard should preserve fn return value even on error")
	assert.True(t, mock.recordCalled, "RecordFailure should be called on fn error")
}

func TestGuard_Blocked_ReturnRateLimited(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{
			Blocked:      true,
			RetryAfter:   30 * time.Second,
			FailureCount: 10,
			Limit:        10,
		},
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	called := false
	val, err := Guard(guard, context.Background(), "client-123", func() (string, error) {
		called = true
		return "should-not-reach", nil
	})

	assert.False(t, called, "fn should NOT be called when blocked")
	assert.Equal(t, "", val, "expected zero value when blocked")
	require.Error(t, err)

	var rateLimited *ErrRateLimited
	require.True(t, errors.As(err, &rateLimited), "expected *ErrRateLimited, got %T", err)
	assert.Equal(t, 30*time.Second, rateLimited.RetryAfter, "expected exact RetryAfter from mock result")
	assert.Equal(t, 10, rateLimited.Limit)
}

func TestGuard_RedisError_FailClosed(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedErr: errRedis,
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	called := false
	val, err := Guard(guard, context.Background(), "client-123", func() (string, error) {
		called = true
		return "should-not-reach", nil
	})

	assert.False(t, called, "fn should NOT be called on Redis error")
	assert.Equal(t, "", val, "expected zero value on infrastructure error")
	require.Error(t, err)

	var infraErr *ErrInfrastructure
	require.True(t, errors.As(err, &infraErr), "expected *ErrInfrastructure, got %T", err)
	assert.ErrorIs(t, infraErr.Cause, errRedis, "ErrInfrastructure should wrap the original Redis error")
}

func TestGuard_RecordFailureError_StillReturnsFnError(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 10},
		recordErr:       errRedis,
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	fnErr := fmt.Errorf("bad credentials")
	val, err := Guard(guard, context.Background(), "client-123", func() (string, error) {
		return "", fnErr
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, fnErr), "expected original fn error, not infra error")
	assert.Equal(t, "", val)

	// Must NOT return ErrInfrastructure — recording is best-effort
	var infraErr *ErrInfrastructure
	assert.False(t, errors.As(err, &infraErr), "should not be ErrInfrastructure")
}

// --- Config propagation test ---

func TestGuard_PropagatesConfigToTracker(t *testing.T) {
	var capturedCfg FailureConfig
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 5},
	}
	// Override IsBlocked to capture config
	origIsBlocked := mock.IsBlocked
	_ = origIsBlocked
	capturedOnIsBlocked := false
	capturedOnRecord := false

	// Use a capturing mock via a wrapper
	capturingMock := &capturingFailureTracker{
		inner:   mock,
		onCheck: func(cfg FailureConfig) { capturedCfg = cfg; capturedOnIsBlocked = true },
		onRecord: func(cfg FailureConfig) {
			if !capturedOnRecord {
				capturedCfg = cfg
			}
			capturedOnRecord = true
		},
	}

	guard := NewFailureGuard(capturingMock, "client", "token", 5, 2*time.Minute, testNopLogger())

	_, _ = Guard(guard, context.Background(), "test-key-123", func() (string, error) {
		return "", fmt.Errorf("fail")
	})

	require.True(t, capturedOnIsBlocked, "IsBlocked should have been called")
	assert.Equal(t, "test-key-123", capturedCfg.Key, "Guard must set cfg.Key from key parameter")
	assert.Equal(t, "client", capturedCfg.Prefix, "Guard must propagate prefix from constructor")
	assert.Equal(t, "token", capturedCfg.Action, "Guard must propagate action from constructor")
	assert.Equal(t, 5, capturedCfg.Limit, "Guard must propagate limit from constructor")
	assert.Equal(t, 2*time.Minute, capturedCfg.Window, "Guard must propagate window from constructor")
	require.True(t, capturedOnRecord, "RecordFailure should have been called on fn error")
}

// capturingFailureTracker wraps a mockFailureTracker to capture FailureConfig values.
type capturingFailureTracker struct {
	inner    *mockFailureTracker
	onCheck  func(FailureConfig)
	onRecord func(FailureConfig)
}

func (c *capturingFailureTracker) IsBlocked(ctx context.Context, cfg FailureConfig) (*FailureCheckResult, error) {
	if c.onCheck != nil {
		c.onCheck(cfg)
	}
	return c.inner.IsBlocked(ctx, cfg)
}

func (c *capturingFailureTracker) RecordFailure(ctx context.Context, cfg FailureConfig) error {
	if c.onRecord != nil {
		c.onRecord(cfg)
	}
	return c.inner.RecordFailure(ctx, cfg)
}

// --- Generic type tests ---

func TestGuard_GenericTypes_Bool(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 10},
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	val, err := Guard(guard, context.Background(), "client-123", func() (bool, error) {
		return true, nil
	})

	require.NoError(t, err)
	assert.True(t, val)
}

type testGuardResult struct {
	Name  string
	Count int
}

func TestGuard_GenericTypes_StructPointer(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false, FailureCount: 0, Limit: 10},
	}
	guard := NewFailureGuard(mock, "client", "token", 10, time.Minute, testNopLogger())

	expected := &testGuardResult{Name: "test", Count: 42}
	val, err := Guard(guard, context.Background(), "client-123", func() (*testGuardResult, error) {
		return expected, nil
	})

	require.NoError(t, err)
	assert.Equal(t, expected, val)
}

func TestGuard_GenericTypes_StructPointer_Blocked_ReturnsNil(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{
			Blocked:      true,
			RetryAfter:   30 * time.Second,
			FailureCount: 5,
			Limit:        5,
		},
	}
	guard := NewFailureGuard(mock, "client", "token", 5, time.Minute, testNopLogger())

	called := false
	val, err := Guard(guard, context.Background(), "client-123", func() (*testGuardResult, error) {
		called = true
		return nil, nil
	})
	assert.False(t, called, "fn should not be called when blocked")

	require.Error(t, err)
	assert.Nil(t, val, "expected nil zero value for pointer type")
}

// --- Constructor nil-check tests ---

func TestNewFailureGuard_PanicsOnNilTracker(t *testing.T) {
	require.Panics(t, func() {
		NewFailureGuard(nil, "client", "token", 10, time.Minute, testNopLogger())
	})
}

func TestNewFailureGuard_PanicsOnNilLogger(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "client", "token", 10, time.Minute, nil)
	})
}

func TestNewFailureGuard_PanicsOnEmptyPrefix(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "", "token", 10, time.Minute, testNopLogger())
	})
}

func TestNewFailureGuard_PanicsOnEmptyAction(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "client", "", 10, time.Minute, testNopLogger())
	})
}

func TestNewFailureGuard_PanicsOnZeroLimit(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "client", "token", 0, time.Minute, testNopLogger())
	})
}

func TestNewFailureGuard_PanicsOnNegativeLimit(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "client", "token", -1, time.Minute, testNopLogger())
	})
}

func TestNewFailureGuard_PanicsOnZeroWindow(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "client", "token", 10, 0, testNopLogger())
	})
}

func TestNewFailureGuard_PanicsOnNegativeWindow(t *testing.T) {
	mock := &mockFailureTracker{
		isBlockedResult: &FailureCheckResult{Blocked: false},
	}
	require.Panics(t, func() {
		NewFailureGuard(mock, "client", "token", 10, -time.Second, testNopLogger())
	})
}
