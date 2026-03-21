package ratelimiter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	redisclient "github.com/turnkeystaffing/go-redis"
)

// errRedis is a sentinel error for Redis failures in tests.
var errRedis = fmt.Errorf("redis connection failed")

// testNopLogger returns a no-op logger for tests. Shared across all test files.
func testNopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mockErrorIntCmd implements redisclient.IntCommand returning an error from Result().
// Shared across test files for per-command error simulation.
type mockErrorIntCmd struct {
	err error
}

func (c *mockErrorIntCmd) Val() int64             { return 0 }
func (c *mockErrorIntCmd) Result() (int64, error) { return 0, c.err }

// errorIncrPipeliner returns mockErrorIntCmd for all INCR calls, simulating per-command errors.
// Shared across test files for fail-closed testing.
type errorIncrPipeliner struct {
	incrErr error
}

func (p *errorIncrPipeliner) Incr(_ context.Context, _ string) redisclient.IntCommand {
	return &mockErrorIntCmd{err: p.incrErr}
}

func (p *errorIncrPipeliner) Expire(_ context.Context, _ string, _ time.Duration) redisclient.BoolCommand {
	return &mockBoolCmd{}
}

func (p *errorIncrPipeliner) Exec(_ context.Context) error { return nil }
