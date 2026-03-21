package ratelimiter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDegradationMonitor_InitialState(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, time.Hour, testNopLogger())
	defer monitor.Stop()

	assert.False(t, monitor.IsDegraded(), "newly created monitor should not be degraded")
}

func TestDegradationMonitor_MarkDegraded(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return false }, time.Hour, testNopLogger())
	defer monitor.Stop()

	monitor.MarkDegraded()
	assert.True(t, monitor.IsDegraded())
}

func TestDegradationMonitor_MarkHealthy(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return false }, time.Hour, testNopLogger())
	defer monitor.Stop()

	monitor.MarkDegraded()
	require.True(t, monitor.IsDegraded())

	monitor.MarkHealthy()
	assert.False(t, monitor.IsDegraded())
}

func TestDegradationMonitor_MarkDegraded_Idempotent(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return false }, time.Hour, testNopLogger())
	defer monitor.Stop()

	monitor.MarkDegraded()
	monitor.MarkDegraded()
	monitor.MarkDegraded()
	assert.True(t, monitor.IsDegraded())
}

func TestDegradationMonitor_MarkHealthy_Idempotent(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return false }, time.Hour, testNopLogger())
	defer monitor.Stop()

	// Already healthy — calling MarkHealthy should not panic or change state
	monitor.MarkHealthy()
	assert.False(t, monitor.IsDegraded())
}

func TestDegradationMonitor_RecoveryLoop_RestoresHealth(t *testing.T) {
	healthy := atomic.Bool{}
	healthy.Store(false)

	monitor := NewDegradationMonitor(func() bool { return healthy.Load() }, 10*time.Millisecond, testNopLogger())
	defer monitor.Stop()

	monitor.MarkDegraded()
	require.True(t, monitor.IsDegraded())

	// Signal recovery
	healthy.Store(true)
	// Wait for at least one tick
	time.Sleep(50 * time.Millisecond)

	assert.False(t, monitor.IsDegraded(), "monitor should recover after recovery check returns true")
}

func TestDegradationMonitor_RecoveryLoop_SkipsWhenHealthy(t *testing.T) {
	callCount := atomic.Int32{}
	monitor := NewDegradationMonitor(func() bool {
		callCount.Add(1)
		return true
	}, 10*time.Millisecond, testNopLogger())
	defer monitor.Stop()

	// Monitor starts healthy — recovery check should fire but MarkHealthy is a no-op
	time.Sleep(50 * time.Millisecond)

	// Recovery check runs on tick, but IsDegraded() is false so it short-circuits
	assert.False(t, monitor.IsDegraded())
}

func TestDegradationMonitor_RecoveryLoop_NeverRecovers(t *testing.T) {
	// Recovery check always returns false — system stays degraded
	monitor := NewDegradationMonitor(func() bool { return false }, 10*time.Millisecond, testNopLogger())
	defer monitor.Stop()

	monitor.MarkDegraded()
	time.Sleep(50 * time.Millisecond)

	assert.True(t, monitor.IsDegraded(), "should stay degraded when recovery check returns false")
}

func TestDegradationMonitor_Stop_TerminatesGoroutine(t *testing.T) {
	callCount := atomic.Int32{}
	monitor := NewDegradationMonitor(func() bool {
		callCount.Add(1)
		return false
	}, 10*time.Millisecond, testNopLogger())

	monitor.MarkDegraded()
	time.Sleep(50 * time.Millisecond)
	monitor.Stop()

	// Allow any in-flight tick to complete
	time.Sleep(20 * time.Millisecond)
	countAfterStop := callCount.Load()

	// Wait longer — no new calls should arrive
	time.Sleep(80 * time.Millisecond)
	countLater := callCount.Load()

	assert.Equal(t, countAfterStop, countLater, "no more recovery checks should fire after Stop()")
}

func TestDegradationMonitor_Stop_DoubleClose_Safe(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, time.Hour, testNopLogger())

	// Calling Stop() twice should not panic
	monitor.Stop()
	assert.NotPanics(t, func() {
		monitor.Stop()
	})
}

func TestDegradationMonitor_ConcurrentAccess(t *testing.T) {
	monitor := NewDegradationMonitor(func() bool { return true }, 10*time.Millisecond, testNopLogger())
	defer monitor.Stop()

	var wg sync.WaitGroup
	const goroutines = 50

	// Half the goroutines mark degraded, half read state
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%3 == 0 {
				monitor.MarkDegraded()
			} else if n%3 == 1 {
				monitor.MarkHealthy()
			} else {
				_ = monitor.IsDegraded()
			}
		}(i)
	}

	wg.Wait()
	// No panics or data races — that's the assertion (run with -race flag)
}

func TestDegradationMonitor_NegativeInterval_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "NewDegradationMonitor: interval must be positive", func() {
		NewDegradationMonitor(func() bool { return true }, -1*time.Second, testNopLogger())
	})
}
