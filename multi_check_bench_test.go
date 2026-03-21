package ratelimiter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkMultiCheckLimiter_Check_ThreeDimensions(b *testing.B) {
	client := newTestMultiCheckClient()
	limiter := NewMultiCheckLimiter(client, testNopLogger())
	dims := []CheckDimension{
		{Prefix: "ip", Key: "192.168.1.1", Action: "login", Limit: 30, Window: time.Minute},
		{Prefix: "email", Key: "user@example.com", Action: "login", Limit: 5, Window: time.Minute},
		{Prefix: "session", Key: "sess-abc123", Action: "login", Limit: 10, Window: time.Minute},
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		atomic.StoreInt64(&client.counter, 0)
		_, err := limiter.Check(ctx, dims)
		if err != nil {
			b.Fatal(err)
		}
	}
}
