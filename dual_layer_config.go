package ratelimiter

import "time"

// EndpointLimit defines rate limits for a specific endpoint.
// Both client and IP limits are checked independently - both must pass.
type EndpointLimit struct {
	// ClientLimit is the per-client_id limit (0 = skip client check for public endpoints)
	ClientLimit int
	// IPLimit is the per-IP address limit
	IPLimit int
}

// DualLayerConfig holds configuration for dual-layer rate limiting.
// Used by OAuth and BFF gateways for per-client + per-IP rate limiting.
type DualLayerConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool
	// Window is the time window for rate limiting (typically 1 minute)
	Window time.Duration
	// Endpoints maps endpoint names to their specific limits
	Endpoints map[string]EndpointLimit
}

// GetEndpointLimit returns the limit for a specific endpoint.
// Returns zero limits if endpoint is not configured (allows all requests).
func (c *DualLayerConfig) GetEndpointLimit(endpoint string) EndpointLimit {
	if limit, ok := c.Endpoints[endpoint]; ok {
		return limit
	}
	return EndpointLimit{} // Zero limits = no rate limiting for unknown endpoints
}
