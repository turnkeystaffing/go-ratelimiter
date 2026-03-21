package ratelimiter

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	buckets     map[string]*bucket
	mutex       sync.RWMutex
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

// bucket represents a rate limiting bucket for a specific key
type bucket struct {
	tokens     int
	maxTokens  int
	lastRefill time.Time
	window     time.Duration
}

// NewRateLimiter creates a new in-memory rate limiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		buckets:     make(map[string]*bucket),
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Close stops the cleanup goroutine. Safe to call multiple times.
func (rl *RateLimiter) Close() error {
	rl.closeOnce.Do(func() {
		close(rl.stopCleanup)
	})
	return nil
}

var _ io.Closer = (*RateLimiter)(nil)

// CheckRateLimit checks if an action is allowed under the rate limit
func (rl *RateLimiter) CheckRateLimit(_ context.Context, key string, action string, limit int, window time.Duration) error {
	bucketKey := fmt.Sprintf("%s:%s", sanitizeKeySegment(key), sanitizeKeySegment(action))

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	b, exists := rl.buckets[bucketKey]

	if !exists {
		// Create new bucket
		b = &bucket{
			tokens:     limit - 1, // Use one token for this request
			maxTokens:  limit,
			lastRefill: now,
			window:     window,
		}
		rl.buckets[bucketKey] = b
		return nil
	}

	// Refill tokens based on time passed
	rl.refillBucket(b, now)

	// Check if we have tokens available
	if b.tokens <= 0 {
		retryAfter := b.window - time.Since(b.lastRefill)
		if retryAfter < 0 {
			retryAfter = b.window
		}
		return &ErrRateLimited{RetryAfter: retryAfter, Limit: limit}
	}

	// Consume a token
	b.tokens--

	return nil
}

// refillBucket refills tokens in a bucket based on the time window
func (rl *RateLimiter) refillBucket(b *bucket, now time.Time) {
	// If the window has completely passed, reset the bucket
	if now.Sub(b.lastRefill) >= b.window {
		b.tokens = b.maxTokens
		b.lastRefill = now
	}
}

// cleanup removes old buckets to prevent memory leaks
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCleanup:
			return
		case <-ticker.C:
			rl.mutex.Lock()
			now := time.Now()

			for key, bucket := range rl.buckets {
				// Remove buckets that haven't been used for 2x their window
				if now.Sub(bucket.lastRefill) > bucket.window*2 {
					delete(rl.buckets, key)
				}
			}

			rl.mutex.Unlock()
		}
	}
}

// GetBucketStatus returns the current status of a rate limit bucket for debugging
func (rl *RateLimiter) GetBucketStatus(_ context.Context, key string, action string) (int, int, time.Time) {
	bucketKey := fmt.Sprintf("%s:%s", sanitizeKeySegment(key), sanitizeKeySegment(action))

	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	b, exists := rl.buckets[bucketKey]
	if !exists {
		return 0, 0, time.Time{}
	}

	return b.tokens, b.maxTokens, b.lastRefill
}
