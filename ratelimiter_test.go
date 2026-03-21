package ratelimiter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	assert.NotNil(t, rl)
	assert.NotNil(t, rl.buckets)
	assert.Equal(t, 0, len(rl.buckets))
}

func TestRateLimiter_CheckRateLimit_NewUser(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "test_action"
	limit := 5
	window := time.Minute

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	bucketKey := sanitizeKeySegment(key) + ":" + sanitizeKeySegment(action)
	rl.mutex.RLock()
	bucket, exists := rl.buckets[bucketKey]
	rl.mutex.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, limit-1, bucket.tokens)
	assert.Equal(t, limit, bucket.maxTokens)
	assert.Equal(t, window, bucket.window)
}

func TestRateLimiter_CheckRateLimit_WithinLimit(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "test_action"
	limit := 3
	window := time.Minute

	for i := 0; i < limit; i++ {
		err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.NoError(t, err, "Request %d should succeed", i+1)
	}

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.Error(t, err)
	var rateLimitErr *ErrRateLimited
	assert.True(t, errors.As(err, &rateLimitErr))
	assert.Equal(t, limit, rateLimitErr.Limit)
	assert.True(t, rateLimitErr.RetryAfter > 0)
}

func TestRateLimiter_CheckRateLimit_ExceedsLimit(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "login"
	limit := 2
	window := time.Minute

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.Error(t, err)
	var rateLimitErr *ErrRateLimited
	assert.True(t, errors.As(err, &rateLimitErr))
	assert.Equal(t, limit, rateLimitErr.Limit)
}

func TestRateLimiter_CheckRateLimit_TokenRefill(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "test_action"
	limit := 2
	window := 100 * time.Millisecond

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.Error(t, err)

	time.Sleep(110 * time.Millisecond)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)
}

func TestRateLimiter_CheckRateLimit_DifferentUsers(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	user1 := "user-1"
	user2 := "user-2"
	action := "test_action"
	limit := 1
	window := time.Minute

	err := rl.CheckRateLimit(context.Background(), user1, action, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), user1, action, limit, window)
	assert.Error(t, err)

	err = rl.CheckRateLimit(context.Background(), user2, action, limit, window)
	assert.NoError(t, err)
}

func TestRateLimiter_CheckRateLimit_DifferentActions(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action1 := "login"
	action2 := "password_reset"
	limit := 1
	window := time.Minute

	err := rl.CheckRateLimit(context.Background(), key, action1, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action1, limit, window)
	assert.Error(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action2, limit, window)
	assert.NoError(t, err)
}

func TestRateLimiter_CheckRateLimit_RetryAfterComputation(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-retry"
	action := "test"
	limit := 1
	window := time.Minute

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.Error(t, err)
	var rateLimitErr *ErrRateLimited
	assert.True(t, errors.As(err, &rateLimitErr))
	assert.Equal(t, limit, rateLimitErr.Limit)
	assert.True(t, rateLimitErr.RetryAfter > 0)
	assert.True(t, rateLimitErr.RetryAfter <= window)
}

func TestRateLimiter_GetBucketStatus_ExistingBucket(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "test_action"
	limit := 5
	window := time.Minute

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	count, maxCount, lastRefill := rl.GetBucketStatus(context.Background(), key, action)
	assert.Equal(t, limit-1, count)
	assert.Equal(t, limit, maxCount)
	assert.False(t, lastRefill.IsZero())
}

func TestRateLimiter_GetBucketStatus_NonExistentBucket(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "nonexistent_action"

	count, maxCount, lastRefill := rl.GetBucketStatus(context.Background(), key, action)
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, maxCount)
	assert.True(t, lastRefill.IsZero())
}

func TestRateLimiter_GetBucketStatus_AfterRefill(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-abc-123"
	action := "test_action"
	limit := 3
	window := 50 * time.Millisecond

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	count, _, _ := rl.GetBucketStatus(context.Background(), key, action)
	assert.Equal(t, limit-1, count)

	time.Sleep(60 * time.Millisecond)

	err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	count, maxCount, lastRefill := rl.GetBucketStatus(context.Background(), key, action)
	assert.Equal(t, limit-1, count)
	assert.Equal(t, limit, maxCount)
	assert.False(t, lastRefill.IsZero())
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-concurrent"
	action := "concurrent_test"
	limit := 10
	window := time.Minute

	var wg sync.WaitGroup
	var successCount int32
	var errorCount int32
	var mutex sync.Mutex

	numGoroutines := 20
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := rl.CheckRateLimit(context.Background(), key, action, limit, window)

			mutex.Lock()
			if err == nil {
				successCount++
			} else {
				errorCount++
			}
			mutex.Unlock()
		}()
	}

	wg.Wait()

	assert.Equal(t, int32(limit), successCount)
	assert.Equal(t, int32(numGoroutines-limit), errorCount)
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-cleanup"
	action := "cleanup_test"
	limit := 5
	window := 50 * time.Millisecond

	err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
	assert.NoError(t, err)

	_, _, lastRefill := rl.GetBucketStatus(context.Background(), key, action)
	assert.False(t, lastRefill.IsZero())

	bucketKey := sanitizeKeySegment(key) + ":" + sanitizeKeySegment(action)

	rl.mutex.RLock()
	bucket := rl.buckets[bucketKey]
	rl.mutex.RUnlock()

	rl.mutex.Lock()
	bucket.lastRefill = time.Now().Add(-10 * time.Minute)
	rl.mutex.Unlock()

	_, _, lastRefillAfter := rl.GetBucketStatus(context.Background(), key, action)
	assert.False(t, lastRefillAfter.IsZero())
}

func TestRateLimiter_EdgeCases(t *testing.T) {
	t.Run("zero limit", func(t *testing.T) {
		rl := NewRateLimiter()
		defer rl.Stop()
		key := "user-zero"
		action := "zero_limit"
		limit := 0
		window := time.Minute

		err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.NoError(t, err)

		count, maxCount, lastRefill := rl.GetBucketStatus(context.Background(), key, action)
		assert.Equal(t, -1, count)
		assert.Equal(t, 0, maxCount)
		assert.False(t, lastRefill.IsZero())

		err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.Error(t, err)
		var rateLimitErr *ErrRateLimited
		assert.True(t, errors.As(err, &rateLimitErr))
	})

	t.Run("very short window", func(t *testing.T) {
		rl := NewRateLimiter()
		defer rl.Stop()
		key := "user-short"
		action := "short_window"
		limit := 2
		window := time.Nanosecond

		err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.NoError(t, err)

		time.Sleep(time.Microsecond)

		err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.NoError(t, err)
	})

	t.Run("very long window", func(t *testing.T) {
		rl := NewRateLimiter()
		defer rl.Stop()
		key := "user-long"
		action := "long_window"
		limit := 2
		window := 24 * time.Hour

		err := rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.NoError(t, err)

		err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.NoError(t, err)

		err = rl.CheckRateLimit(context.Background(), key, action, limit, window)
		assert.Error(t, err)
	})
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter()

	// Use the limiter
	err := rl.CheckRateLimit(context.Background(), "key", "action", 5, time.Minute)
	assert.NoError(t, err)

	// Stop should not panic
	rl.Stop()

	// Limiter should still be usable for reads after Stop (cleanup goroutine stopped, but data intact)
	count, max, _ := rl.GetBucketStatus(context.Background(), "key", "action")
	assert.Equal(t, 4, count)
	assert.Equal(t, 5, max)
}

func TestRateLimiter_Interface_Compliance(t *testing.T) {
	concreteRL := NewRateLimiter()
	defer concreteRL.Stop()
	var rl RateLimiterInterface = concreteRL
	assert.NotNil(t, rl)

	key := "user-interface"
	action := "interface_test"

	err := rl.CheckRateLimit(context.Background(), key, action, 5, time.Minute)
	assert.NoError(t, err)

	count, maxCount, lastRefill := rl.GetBucketStatus(context.Background(), key, action)
	assert.Equal(t, 4, count)
	assert.Equal(t, 5, maxCount)
	assert.False(t, lastRefill.IsZero())
}

// Benchmark tests
func BenchmarkRateLimiter_CheckRateLimit(b *testing.B) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-bench"
	action := "benchmark"
	limit := 1000000
	window := time.Hour

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = rl.CheckRateLimit(context.Background(), key, action, limit, window)
		}
	})
}

func BenchmarkRateLimiter_GetBucketStatus(b *testing.B) {
	rl := NewRateLimiter()
	defer rl.Stop()
	key := "user-bench"
	action := "benchmark"
	limit := 1000
	window := time.Hour

	_ = rl.CheckRateLimit(context.Background(), key, action, limit, window)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = rl.GetBucketStatus(context.Background(), key, action)
		}
	})
}

func BenchmarkRateLimiter_ConcurrentDifferentUsers(b *testing.B) {
	rl := NewRateLimiter()
	defer rl.Stop()
	action := "benchmark"
	limit := 1000
	window := time.Hour

	b.ResetTimer()
	var counter int32
	var mu sync.Mutex
	b.RunParallel(func(pb *testing.PB) {
		mu.Lock()
		counter++
		key := "user-" + string(rune('A'+counter%26))
		mu.Unlock()
		for pb.Next() {
			_ = rl.CheckRateLimit(context.Background(), key, action, limit, window)
		}
	})
}
