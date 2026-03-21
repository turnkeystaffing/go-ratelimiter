package ratelimiter

import (
	"context"
	"errors"
	"testing"
	"time"
)

// testOAuthConfig returns a test OAuth rate limit configuration.
func testOAuthConfig() *DualLayerConfig {
	return &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"authorize":  {ClientLimit: 10, IPLimit: 20},
			"token":      {ClientLimit: 60, IPLimit: 100},
			"introspect": {ClientLimit: 60, IPLimit: 100},
			"revoke":     {ClientLimit: 60, IPLimit: 100},
			"discovery":  {ClientLimit: 0, IPLimit: 100},
			"jwks":       {ClientLimit: 0, IPLimit: 100},
		},
	}
}

// testBFFConfig returns a test BFF rate limit configuration.
func testBFFConfig() *DualLayerConfig {
	return &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"login":    {ClientLimit: 0, IPLimit: 30},
			"token":    {ClientLimit: 0, IPLimit: 120},
			"refresh":  {ClientLimit: 0, IPLimit: 120},
			"logout":   {ClientLimit: 0, IPLimit: 60},
			"userinfo": {ClientLimit: 0, IPLimit: 200},
			"callback": {ClientLimit: 0, IPLimit: 100},
		},
	}
}

func TestDualLayerRateLimiter_Check(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		clientID  string
		ipAddress string
		config    *DualLayerConfig
		setup     func(*RateLimiter)
		wantErr   bool
	}{
		{
			name:      "allows request when under limits",
			endpoint:  "token",
			clientID:  "client-123",
			ipAddress: "192.168.1.1",
			config:    testOAuthConfig(),
			wantErr:   false,
		},
		{
			name:      "allows request when rate limiting disabled",
			endpoint:  "token",
			clientID:  "client-123",
			ipAddress: "192.168.1.1",
			config:    &DualLayerConfig{Enabled: false},
			wantErr:   false,
		},
		{
			name:      "allows request for public endpoint without client_id",
			endpoint:  "discovery",
			clientID:  "",
			ipAddress: "192.168.1.1",
			config:    testOAuthConfig(),
			wantErr:   false,
		},
		{
			name:      "allows request for unknown endpoint (no limits)",
			endpoint:  "unknown",
			clientID:  "client-123",
			ipAddress: "192.168.1.1",
			config:    testOAuthConfig(),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLimiter := NewRateLimiter()
			defer baseLimiter.Stop()
			if tt.setup != nil {
				tt.setup(baseLimiter)
			}

			limiter := NewDualLayerRateLimiter(baseLimiter, tt.config, "oauth", testNopLogger())
			err := limiter.Check(context.Background(), tt.endpoint, tt.clientID, tt.ipAddress)

			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDualLayerRateLimiter_ClientLimitExceeded(t *testing.T) {
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"authorize": {ClientLimit: 3, IPLimit: 100},
		},
	}

	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	for i := 0; i < 3; i++ {
		err := limiter.Check(context.Background(), "authorize", "client-123", "192.168.1.1")
		if err != nil {
			t.Fatalf("Request %d should be allowed: %v", i+1, err)
		}
	}

	err := limiter.Check(context.Background(), "authorize", "client-123", "192.168.1.1")
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("Expected *ErrRateLimited, got %v", err)
	} else {
		if rateLimitErr.Limit != 3 {
			t.Errorf("Expected Limit=3, got %d", rateLimitErr.Limit)
		}
		if rateLimitErr.RetryAfter <= 0 {
			t.Error("Expected positive RetryAfter")
		}
	}

	err = limiter.Check(context.Background(), "authorize", "client-456", "192.168.1.1")
	if err != nil {
		t.Errorf("Different client should be allowed: %v", err)
	}
}

func TestDualLayerRateLimiter_IPLimitExceeded(t *testing.T) {
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"token": {ClientLimit: 100, IPLimit: 3},
		},
	}

	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	for i := 0; i < 3; i++ {
		clientID := "client-" + string(rune('a'+i))
		err := limiter.Check(context.Background(), "token", clientID, "192.168.1.1")
		if err != nil {
			t.Fatalf("Request %d should be allowed: %v", i+1, err)
		}
	}

	err := limiter.Check(context.Background(), "token", "client-d", "192.168.1.1")
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("Expected *ErrRateLimited, got %v", err)
	} else {
		if rateLimitErr.Limit != 3 {
			t.Errorf("Expected Limit=3, got %d", rateLimitErr.Limit)
		}
	}

	err = limiter.Check(context.Background(), "token", "client-d", "10.0.0.1")
	if err != nil {
		t.Errorf("Different IP should be allowed: %v", err)
	}
}

func TestDualLayerRateLimiter_CheckWithDetails(t *testing.T) {
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"authorize": {ClientLimit: 2, IPLimit: 5},
		},
	}

	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	result := limiter.CheckWithDetails(context.Background(), "authorize", "client-123", "192.168.1.1")
	if !result.Allowed {
		t.Error("First request should be allowed")
	}
	if result.ClientLimit != 2 {
		t.Errorf("ClientLimit = %d, want 2", result.ClientLimit)
	}
	if result.IPLimit != 5 {
		t.Errorf("IPLimit = %d, want 5", result.IPLimit)
	}

	result = limiter.CheckWithDetails(context.Background(), "authorize", "client-123", "192.168.1.1")
	if !result.Allowed {
		t.Error("Second request should be allowed")
	}
	if result.ClientCount != 2 {
		t.Errorf("ClientCount = %d, want 2", result.ClientCount)
	}

	result = limiter.CheckWithDetails(context.Background(), "authorize", "client-123", "192.168.1.1")
	if result.Allowed {
		t.Error("Third request should be denied")
	}
	if result.LimitType != "client" {
		t.Errorf("LimitType = %s, want client", result.LimitType)
	}
	if result.RetryAfter <= 0 {
		t.Error("RetryAfter should be positive")
	}
}

func TestDualLayerRateLimiter_PublicEndpoint(t *testing.T) {
	config := testOAuthConfig()
	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	for i := 0; i < 50; i++ {
		err := limiter.Check(context.Background(), "discovery", "", "192.168.1.1")
		if err != nil {
			t.Fatalf("Request %d should be allowed for public endpoint: %v", i+1, err)
		}
	}

	var hitLimit bool
	for i := 50; i < 150; i++ {
		err := limiter.Check(context.Background(), "discovery", "", "192.168.1.1")
		var rateLimitErr *ErrRateLimited
		if errors.As(err, &rateLimitErr) {
			hitLimit = true
			break
		}
	}
	if !hitLimit {
		t.Error("Expected to hit IP rate limit for discovery endpoint")
	}
}

func TestDualLayerRateLimiter_GetStatus(t *testing.T) {
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"token": {ClientLimit: 10, IPLimit: 20},
		},
	}

	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	for i := 0; i < 5; i++ {
		_ = limiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	}

	status := limiter.GetStatus(context.Background(), "token", "client-123", "192.168.1.1")
	if status.ClientCount != 5 {
		t.Errorf("ClientCount = %d, want 5", status.ClientCount)
	}
	if status.IPCount != 5 {
		t.Errorf("IPCount = %d, want 5", status.IPCount)
	}
	if !status.Allowed {
		t.Error("Status should show allowed (under limits)")
	}

	status2 := limiter.GetStatus(context.Background(), "token", "client-123", "192.168.1.1")
	if status2.ClientCount != 5 {
		t.Errorf("Second GetStatus ClientCount = %d, want 5", status2.ClientCount)
	}
}

func TestDualLayerRateLimiter_IsEnabled(t *testing.T) {
	enabledConfig := &DualLayerConfig{Enabled: true}
	disabledConfig := &DualLayerConfig{Enabled: false}

	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()

	enabledLimiter := NewDualLayerRateLimiter(baseLimiter, enabledConfig, "oauth", testNopLogger())
	if !enabledLimiter.IsEnabled() {
		t.Error("Expected IsEnabled() = true")
	}

	disabledLimiter := NewDualLayerRateLimiter(baseLimiter, disabledConfig, "oauth", testNopLogger())
	if disabledLimiter.IsEnabled() {
		t.Error("Expected IsEnabled() = false")
	}
}

func TestDualLayerRateLimiter_DifferentPrefixes(t *testing.T) {
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"token": {ClientLimit: 2, IPLimit: 100},
		},
	}

	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	oauthLimiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())
	bffLimiter := NewDualLayerRateLimiter(baseLimiter, config, "bff", testNopLogger())

	for i := 0; i < 2; i++ {
		_ = oauthLimiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	}

	err := oauthLimiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Error("OAuth limiter should block request")
	}

	err = bffLimiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	if err != nil {
		t.Errorf("BFF limiter should allow request: %v", err)
	}
}

func TestDualLayerRateLimiter_InfraErrorPropagation(t *testing.T) {
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"token": {ClientLimit: 10, IPLimit: 20},
		},
	}

	infraErr := &ErrInfrastructure{Cause: errors.New("redis connection refused")}
	failingLimiter := &infraErrorLimiter{err: infraErr}
	limiter := NewDualLayerRateLimiter(failingLimiter, config, "oauth", testNopLogger())

	// Check() should propagate the infrastructure error, not wrap in *ErrRateLimited
	err := limiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	var rateLimited *ErrRateLimited
	if errors.As(err, &rateLimited) {
		t.Error("Infrastructure error should NOT be converted to *ErrRateLimited")
	}

	var infraErrResult *ErrInfrastructure
	if !errors.As(err, &infraErrResult) {
		t.Errorf("Expected *ErrInfrastructure, got %T: %v", err, err)
	}

	// CheckWithDetails should set InfraError field
	result := limiter.CheckWithDetails(context.Background(), "token", "client-123", "192.168.1.1")
	if result.Allowed {
		t.Error("Should not be allowed on infrastructure error")
	}
	if result.InfraError == nil {
		t.Error("InfraError should be set on infrastructure failure")
	}
}

// infraErrorLimiter always returns an infrastructure error for testing
type infraErrorLimiter struct {
	err error
}

func (l *infraErrorLimiter) CheckRateLimit(_ context.Context, _ string, _ string, _ int, _ time.Duration) error {
	return l.err
}

func (l *infraErrorLimiter) GetBucketStatus(_ context.Context, _ string, _ string) (int, int, time.Time) {
	return 0, 0, time.Time{}
}

func TestDualLayerRateLimiter_GetConfig(t *testing.T) {
	config := testOAuthConfig()
	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	got := limiter.GetConfig()
	if got != config {
		t.Error("GetConfig() should return the same config pointer")
	}
	if !got.Enabled {
		t.Error("Expected Enabled=true")
	}
	if got.Window != time.Minute {
		t.Errorf("Expected Window=1m, got %v", got.Window)
	}
}

func TestDualLayerRateLimiter_InfraError_IPPath(t *testing.T) {
	// Config with no client limit, only IP limit — ensures infra error hits IP path
	config := &DualLayerConfig{
		Enabled: true,
		Window:  time.Minute,
		Endpoints: map[string]EndpointLimit{
			"login": {ClientLimit: 0, IPLimit: 30},
		},
	}

	infraErr := &ErrInfrastructure{Cause: errors.New("redis connection refused")}
	failingLimiter := &infraErrorLimiter{err: infraErr}
	limiter := NewDualLayerRateLimiter(failingLimiter, config, "bff", testNopLogger())

	// Check() should propagate the infrastructure error from the IP path
	err := limiter.Check(context.Background(), "login", "", "192.168.1.1")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	var rateLimited *ErrRateLimited
	if errors.As(err, &rateLimited) {
		t.Error("IP infra error should NOT be converted to *ErrRateLimited")
	}

	var infraErrResult *ErrInfrastructure
	if !errors.As(err, &infraErrResult) {
		t.Errorf("Should be *ErrInfrastructure from IP path, got %T: %v", err, err)
	}

	// CheckWithDetails should set InfraError field and LimitType="ip"
	result := limiter.CheckWithDetails(context.Background(), "login", "", "192.168.1.1")
	if result.Allowed {
		t.Error("Should not be allowed on IP infrastructure error")
	}
	if result.InfraError == nil {
		t.Error("InfraError should be set on IP infrastructure failure")
	}
	if result.LimitType != "ip" {
		t.Errorf("LimitType = %s, want ip", result.LimitType)
	}
	if result.RetryAfter != time.Minute {
		t.Errorf("RetryAfter = %v, want 1m", result.RetryAfter)
	}
}

func TestDualLayerRateLimiter_CheckWithDetails_Disabled(t *testing.T) {
	config := &DualLayerConfig{Enabled: false}
	baseLimiter := NewRateLimiter()
	defer baseLimiter.Stop()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth", testNopLogger())

	result := limiter.CheckWithDetails(context.Background(), "token", "client-123", "192.168.1.1")
	if !result.Allowed {
		t.Error("Disabled config should allow all requests")
	}
	if result.LimitType != "" {
		t.Errorf("LimitType = %s, want empty", result.LimitType)
	}
	if result.RetryAfter != 0 {
		t.Errorf("RetryAfter = %v, want 0", result.RetryAfter)
	}
	if result.InfraError != nil {
		t.Errorf("InfraError should be nil, got %v", result.InfraError)
	}
}

func TestDualLayerConfig_GetEndpointLimit(t *testing.T) {
	config := &DualLayerConfig{
		Endpoints: map[string]EndpointLimit{
			"token": {ClientLimit: 60, IPLimit: 100},
		},
	}

	limits := config.GetEndpointLimit("token")
	if limits.ClientLimit != 60 || limits.IPLimit != 100 {
		t.Errorf("Expected {60, 100}, got {%d, %d}", limits.ClientLimit, limits.IPLimit)
	}

	limits = config.GetEndpointLimit("unknown")
	if limits.ClientLimit != 0 || limits.IPLimit != 0 {
		t.Errorf("Expected {0, 0}, got {%d, %d}", limits.ClientLimit, limits.IPLimit)
	}
}
