package ratelimiter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeKeySegment_NoColons(t *testing.T) {
	assert.Equal(t, "simple-key", sanitizeKeySegment("simple-key"))
}

func TestSanitizeKeySegment_WithColons(t *testing.T) {
	// IPv6 address with colons
	assert.Equal(t, "2001%3A0db8%3A%3A1", sanitizeKeySegment("2001:0db8::1"))
}

func TestSanitizeKeySegment_MultipleColons(t *testing.T) {
	assert.Equal(t, "a%3Ab%3Ac%3Ad", sanitizeKeySegment("a:b:c:d"))
}

func TestSanitizeKeySegment_Empty(t *testing.T) {
	assert.Equal(t, "", sanitizeKeySegment(""))
}

func TestSanitizeKeySegment_PreventsCrossKeyCollision(t *testing.T) {
	// These would collide without sanitization:
	// key="a:b" + action="c" → "a:b:c"
	// key="a" + action="b:c" → "a:b:c"
	// With sanitization they produce different keys:
	key1 := sanitizeKeySegment("a:b") + ":" + sanitizeKeySegment("c")
	key2 := sanitizeKeySegment("a") + ":" + sanitizeKeySegment("b:c")
	assert.NotEqual(t, key1, key2, "sanitized keys should not collide")
}
