package ratelimiter

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrRateLimited ---

func TestErrRateLimited_Error_Format(t *testing.T) {
	err := &ErrRateLimited{RetryAfter: 30 * time.Second, Limit: 10}
	assert.Equal(t, "rate limit exceeded, retry after 30s", err.Error())
}

func TestErrRateLimited_Error_SubSecond(t *testing.T) {
	err := &ErrRateLimited{RetryAfter: 500 * time.Millisecond, Limit: 5}
	assert.Equal(t, "rate limit exceeded, retry after 500ms", err.Error())
}

func TestErrRateLimited_ErrorsAs(t *testing.T) {
	var original error = &ErrRateLimited{RetryAfter: time.Minute, Limit: 100}

	var target *ErrRateLimited
	require.True(t, errors.As(original, &target))
	assert.Equal(t, time.Minute, target.RetryAfter)
	assert.Equal(t, 100, target.Limit)
}

func TestErrRateLimited_ErrorsAs_Wrapped(t *testing.T) {
	inner := &ErrRateLimited{RetryAfter: 10 * time.Second, Limit: 5}
	wrapped := fmt.Errorf("context: %w", inner)

	var target *ErrRateLimited
	require.True(t, errors.As(wrapped, &target))
	assert.Equal(t, 10*time.Second, target.RetryAfter)
	assert.Equal(t, 5, target.Limit)
}

func TestErrRateLimited_ImplementsErrorInterface(t *testing.T) {
	var err error = &ErrRateLimited{RetryAfter: time.Second, Limit: 1}
	assert.NotEmpty(t, err.Error())
}

// --- ErrInfrastructure ---

func TestErrInfrastructure_Error_GenericMessage(t *testing.T) {
	cause := errors.New("redis: connection refused")
	err := &ErrInfrastructure{Cause: cause}
	// Error() returns a generic message to avoid leaking infrastructure details
	assert.Equal(t, "rate limit infrastructure error", err.Error())
	// Cause is accessible only via Unwrap()
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrInfrastructure_Error_NilCause(t *testing.T) {
	err := &ErrInfrastructure{Cause: nil}
	assert.Equal(t, "rate limit infrastructure error", err.Error())
}

func TestErrInfrastructure_Unwrap(t *testing.T) {
	cause := errors.New("redis timeout")
	err := &ErrInfrastructure{Cause: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
}

func TestErrInfrastructure_Unwrap_NilCause(t *testing.T) {
	err := &ErrInfrastructure{Cause: nil}
	assert.Nil(t, err.Unwrap())
}

func TestErrInfrastructure_ErrorsAs(t *testing.T) {
	var original error = &ErrInfrastructure{Cause: errors.New("conn reset")}

	var target *ErrInfrastructure
	require.True(t, errors.As(original, &target))
	assert.EqualError(t, target.Cause, "conn reset")
}

func TestErrInfrastructure_ErrorsAs_Wrapped(t *testing.T) {
	inner := &ErrInfrastructure{Cause: errors.New("dns failure")}
	wrapped := fmt.Errorf("rate check failed: %w", inner)

	var target *ErrInfrastructure
	require.True(t, errors.As(wrapped, &target))
	assert.EqualError(t, target.Cause, "dns failure")
}

func TestErrInfrastructure_ErrorsIs_ThroughUnwrap(t *testing.T) {
	sentinel := errors.New("redis unavailable")
	err := &ErrInfrastructure{Cause: sentinel}

	// errors.Is should find the sentinel through Unwrap()
	assert.True(t, errors.Is(err, sentinel))
}

func TestErrRateLimited_NotErrInfrastructure(t *testing.T) {
	var err error = &ErrRateLimited{RetryAfter: time.Second, Limit: 1}

	var infraErr *ErrInfrastructure
	assert.False(t, errors.As(err, &infraErr), "ErrRateLimited should not match ErrInfrastructure")
}

func TestErrInfrastructure_NotErrRateLimited(t *testing.T) {
	var err error = &ErrInfrastructure{Cause: errors.New("test")}

	var rateLimited *ErrRateLimited
	assert.False(t, errors.As(err, &rateLimited), "ErrInfrastructure should not match ErrRateLimited")
}
