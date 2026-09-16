package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func BenchmarkDNSCorrelatorCacheHit(b *testing.B) {
	correlator := newDNSCorrelator(
		16,
		time.Second,
		time.Hour,
		time.Minute,
		dnsResolverFunc(func(context.Context, string) ([]string, error) {
			return []string{"cached.example."}, nil
		}),
		time.Now,
	)
	ip := net.ParseIP("192.0.2.60")
	if got := correlator.Lookup(ip); got == nil {
		b.Fatal("warm DNS lookup returned nil")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if got := correlator.Lookup(ip); got == nil {
			b.Fatal("cached DNS lookup returned nil")
		}
	}
}
