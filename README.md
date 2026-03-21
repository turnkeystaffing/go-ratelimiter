# go-ratelimiter

A production-grade Go rate limiting library with in-memory and Redis backends, automatic failover, and multi-dimension support.

## Features

- **In-memory rate limiter** — token bucket with automatic cleanup
- **Redis rate limiter** — distributed fixed-window counter via atomic pipelines
- **Fallback rate limiter** — automatic degradation from Redis to in-memory with configurable failure thresholds and recovery monitoring
- **Dual-layer rate limiter** — per-client + per-IP limiting for OAuth/BFF endpoints
- **Multi-dimension batched checks** — IP, email, and session limits in a single Redis round-trip
- **Failure tracker** — block identities after repeated failures (e.g., login, 2FA verification)
- **Cooldown checker** — per-identity mutation throttling via atomic `SET NX EX`
- **Decorator** — pre-configured wrapper that simplifies rate limit calls to a single key
- **No-op limiter** — for CLI tools, testing, and environments where rate limiting is disabled
- **Health checker** — integrates with `go-health` to report degradation status
- **Fail-closed** — Redis errors deny requests rather than silently allowing them
- **Key sanitization** — colon escaping prevents key injection (important for IPv6)

## Installation

```bash
go get github.com/turnkeystaffing/go-ratelimiter
```

## Usage

### In-Memory Rate Limiter

```go
rl := ratelimiter.NewRateLimiter()
defer rl.Stop()

err := rl.CheckRateLimit(ctx, "user-123", "login", 5, time.Minute)
if err != nil {
    // rate limited
}
```

### Redis Rate Limiter

```go
rl, err := ratelimiter.NewRateLimiterFromRedis(redisClient, logger)
if err != nil {
    log.Fatal(err)
}

err = rl.CheckRateLimit(ctx, "user-123", "login", 5, time.Minute)
```

### Fallback Rate Limiter (Redis with In-Memory Fallback)

```go
monitor := ratelimiter.NewDegradationMonitor(recoveryCheckFn, 30*time.Second, logger)
defer monitor.Stop()

fl := ratelimiter.NewFallbackRateLimiter(redisLimiter, memoryLimiter, monitor, logger, 3)
err := fl.CheckRateLimit(ctx, "user-123", "login", 5, time.Minute)
```

After 3 consecutive Redis infrastructure errors, the limiter degrades to in-memory. The monitor periodically probes Redis and restores the primary when healthy.

### Decorator (Pre-Configured Limits)

```go
cfg := &ratelimiter.Config{
    Enabled:    true,
    LoginLimit: 5,
    LoginWindow: time.Minute,
}

decorator, _ := ratelimiter.NewLoginRateLimiterFromConfig(baseLimiter, cfg, logger)
err := decorator.CheckRateLimit(ctx, "user-123")
```

### Dual-Layer Rate Limiter (Per-Client + Per-IP)

```go
config := &ratelimiter.DualLayerConfig{
    Enabled: true,
    Window:  time.Minute,
    Endpoints: map[string]ratelimiter.EndpointLimit{
        "/oauth/token": {ClientLimit: 60, IPLimit: 120},
    },
}

dl := ratelimiter.NewDualLayerRateLimiter(baseLimiter, config, "oauth", logger)

err := dl.Check(ctx, "/oauth/token", "client-abc", "192.168.1.1")
// Or with full details:
result := dl.CheckWithDetails(ctx, "/oauth/token", "client-abc", "192.168.1.1")
```

### Multi-Dimension Batched Check

```go
mcl := ratelimiter.NewMultiCheckLimiter(redisClient, logger)

result, err := mcl.Check(ctx, []ratelimiter.CheckDimension{
    {Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 10, Window: time.Minute},
    {Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
})
if !result.Allowed {
    fmt.Printf("blocked by %s, retry after %s\n", result.BlockedBy, result.RetryAfter)
}
```

### Failure Tracker

```go
tracker := ratelimiter.NewFailureTracker(redisClient, logger)
guard := ratelimiter.NewFailureGuard(tracker, "user", "2fa_verify", 5, 15*time.Minute, logger)

result, err := ratelimiter.Guard(guard, ctx, "user-123", func() (MyResult, error) {
    return myService.Verify2FA(ctx, code)
})
```

The guard pre-checks if the key is blocked, executes the function, and records a failure only if it returns an error.

### Cooldown Checker

```go
cc := ratelimiter.NewCooldownChecker(redisClient, logger)

result, err := cc.CheckAndSet(ctx, "user-123", "password_change", 5*time.Minute)
if result.Blocked {
    fmt.Printf("try again in %s\n", result.RetryAfter)
}
```

## Error Handling

All rate limit operations return typed errors for precise handling:

```go
var rateLimited *ratelimiter.ErrRateLimited
if errors.As(err, &rateLimited) {
    // Set Retry-After header, return 429
    w.Header().Set("Retry-After", fmt.Sprintf("%.0f", rateLimited.RetryAfter.Seconds()))
}

var infraErr *ratelimiter.ErrInfrastructure
if errors.As(err, &infraErr) {
    // Redis is down — return 503, not 401
}
```

## Testing

```bash
go test ./...
```

## License

See [LICENSE](LICENSE) for details.