package ratelimiter

import "strings"

// sanitizeKeySegment escapes colons in key segments to prevent key injection.
// Redis keys use colons as delimiters; unsanitized segments containing colons
// could collide with other keys, allowing cross-pollination of rate limit buckets.
// This is especially important for IPv6 addresses which naturally contain colons.
func sanitizeKeySegment(s string) string {
	return strings.ReplaceAll(s, ":", "%3A")
}
