package ratelimiter

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// DegradationMonitor tracks whether the primary rate limiter is degraded.
// When degraded, the FallbackRateLimiter uses the in-memory fallback.
// A background goroutine periodically calls the recovery check function
// to determine if the primary is healthy again.
type DegradationMonitor struct {
	mu            sync.RWMutex
	degraded      bool
	recoveryCheck func() bool
	interval      time.Duration
	stopCh        chan struct{}
	stopOnce      sync.Once
	logger        *slog.Logger
}

// NewDegradationMonitor creates a monitor with a recovery check function and interval.
// recoveryCheck should return true if the primary is healthy.
// interval controls how often the recovery check is called when degraded.
func NewDegradationMonitor(recoveryCheck func() bool, interval time.Duration, logger *slog.Logger) *DegradationMonitor {
	if recoveryCheck == nil {
		panic("NewDegradationMonitor: recoveryCheck cannot be nil")
	}
	if interval <= 0 {
		panic("NewDegradationMonitor: interval must be positive")
	}
	if logger == nil {
		panic("NewDegradationMonitor: logger cannot be nil")
	}
	m := &DegradationMonitor{
		recoveryCheck: recoveryCheck,
		interval:      interval,
		stopCh:        make(chan struct{}),
		logger:        logger,
	}
	go m.recoveryLoop()
	return m
}

// MarkDegraded sets the monitor to degraded state.
func (m *DegradationMonitor) MarkDegraded() {
	m.mu.Lock()
	wasHealthy := !m.degraded
	m.degraded = true
	m.mu.Unlock()
	if wasHealthy {
		m.logger.WarnContext(context.Background(), "rate limiter entering degraded mode")
	}
}

// MarkHealthy sets the monitor to healthy state.
func (m *DegradationMonitor) MarkHealthy() {
	m.mu.Lock()
	wasDegraded := m.degraded
	m.degraded = false
	m.mu.Unlock()
	if wasDegraded {
		m.logger.WarnContext(context.Background(), "rate limiter recovered from degraded mode")
	}
}

// IsDegraded returns whether the monitor is in degraded state.
func (m *DegradationMonitor) IsDegraded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.degraded
}

// Stop stops the background recovery loop. Safe to call multiple times.
func (m *DegradationMonitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// recoveryLoop periodically checks if the primary is healthy when degraded.
func (m *DegradationMonitor) recoveryLoop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if m.IsDegraded() && m.recoveryCheck() {
				m.MarkHealthy()
			}
		}
	}
}
