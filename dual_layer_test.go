package ratelimiter

import (
	"context"
	"errors"
	"testing"
	"time"
)

// testOAuthConfig returns a test OAuth rate limit configuration.
// Mirrors the defaults from internal/bff/config/ratelimit.go.
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
// Mirrors the defaults from internal/bff/config/ratelimit.go.
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
		setup     func(*RateLimiter) // Pre-populate rate limiter
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
			if tt.setup != nil {
				tt.setup(baseLimiter)
			}

			limiter := NewDualLayerRateLimiter(baseLimiter, tt.config, "oauth")
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
			"authorize": {ClientLimit: 3, IPLimit: 100}, // Low client limit for testing
		},
	}

	baseLimiter := NewRateLimiter()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth")

	// Make requests up to the client limit
	for i := 0; i < 3; i++ {
		err := limiter.Check(context.Background(), "authorize", "client-123", "192.168.1.1")
		if err != nil {
			t.Fatalf("Request %d should be allowed: %v", i+1, err)
		}
	}

	// Next request should be blocked (client limit exceeded)
	err := limiter.Check(context.Background(), "authorize", "client-123", "192.168.1.1")
	if !errors.Is(err, ErrRateLimitExceeded) {
		t.Errorf("Expected ErrRateLimitExceeded, got %v", err)
	}

	// Different client should still be allowed
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
			"token": {ClientLimit: 100, IPLimit: 3}, // Low IP limit for testing
		},
	}

	baseLimiter := NewRateLimiter()
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth")

	// Make requests up to the IP limit (different clients, same IP)
	for i := 0; i < 3; i++ {
		clientID := "client-" + string(rune('a'+i))
		err := limiter.Check(context.Background(), "token", clientID, "192.168.1.1")
		if err != nil {
			t.Fatalf("Request %d should be allowed: %v", i+1, err)
		}
	}

	// Next request from same IP should be blocked
	err := limiter.Check(context.Background(), "token", "client-d", "192.168.1.1")
	if !errors.Is(err, ErrRateLimitExceeded) {
		t.Errorf("Expected ErrRateLimitExceeded, got %v", err)
	}

	// Different IP should still be allowed
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
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth")

	// First request
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

	// Second request
	result = limiter.CheckWithDetails(context.Background(), "authorize", "client-123", "192.168.1.1")
	if !result.Allowed {
		t.Error("Second request should be allowed")
	}
	if result.ClientCount != 2 {
		t.Errorf("ClientCount = %d, want 2", result.ClientCount)
	}

	// Third request should exceed client limit
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
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth")

	// Discovery endpoint should skip client check (ClientLimit = 0)
	for i := 0; i < 50; i++ {
		err := limiter.Check(context.Background(), "discovery", "", "192.168.1.1")
		if err != nil {
			t.Fatalf("Request %d should be allowed for public endpoint: %v", i+1, err)
		}
	}

	// Should eventually hit IP limit (100/min)
	var hitLimit bool
	for i := 50; i < 150; i++ {
		err := limiter.Check(context.Background(), "discovery", "", "192.168.1.1")
		if errors.Is(err, ErrRateLimitExceeded) {
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
	limiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth")

	// Make some requests
	for i := 0; i < 5; i++ {
		_ = limiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	}

	// Check status (should not increment counters)
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

	// GetStatus again should return same counts (not incremented)
	status2 := limiter.GetStatus(context.Background(), "token", "client-123", "192.168.1.1")
	if status2.ClientCount != 5 {
		t.Errorf("Second GetStatus ClientCount = %d, want 5", status2.ClientCount)
	}
}

func TestDualLayerRateLimiter_IsEnabled(t *testing.T) {
	enabledConfig := &DualLayerConfig{Enabled: true}
	disabledConfig := &DualLayerConfig{Enabled: false}

	baseLimiter := NewRateLimiter()

	enabledLimiter := NewDualLayerRateLimiter(baseLimiter, enabledConfig, "oauth")
	if !enabledLimiter.IsEnabled() {
		t.Error("Expected IsEnabled() = true")
	}

	disabledLimiter := NewDualLayerRateLimiter(baseLimiter, disabledConfig, "oauth")
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
	oauthLimiter := NewDualLayerRateLimiter(baseLimiter, config, "oauth")
	bffLimiter := NewDualLayerRateLimiter(baseLimiter, config, "bff")

	// Exhaust OAuth client limit
	for i := 0; i < 2; i++ {
		_ = oauthLimiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	}

	// OAuth should be blocked
	err := oauthLimiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	if !errors.Is(err, ErrRateLimitExceeded) {
		t.Error("OAuth limiter should block request")
	}

	// BFF with same client_id should still work (different prefix)
	err = bffLimiter.Check(context.Background(), "token", "client-123", "192.168.1.1")
	if err != nil {
		t.Errorf("BFF limiter should allow request: %v", err)
	}
}

func TestDualLayerConfig_GetEndpointLimit(t *testing.T) {
	config := &DualLayerConfig{
		Endpoints: map[string]EndpointLimit{
			"token": {ClientLimit: 60, IPLimit: 100},
		},
	}

	// Configured endpoint
	limits := config.GetEndpointLimit("token")
	if limits.ClientLimit != 60 || limits.IPLimit != 100 {
		t.Errorf("Expected {60, 100}, got {%d, %d}", limits.ClientLimit, limits.IPLimit)
	}

	// Unconfigured endpoint returns zero limits
	limits = config.GetEndpointLimit("unknown")
	if limits.ClientLimit != 0 || limits.IPLimit != 0 {
		t.Errorf("Expected {0, 0}, got {%d, %d}", limits.ClientLimit, limits.IPLimit)
	}
}
