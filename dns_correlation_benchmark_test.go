package main

import (
	"net"
	"testing"
	"time"
)

func BenchmarkDNSCorrelationLookupGlobal(b *testing.B) {
	base := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	correlator := benchmarkDNSCorrelator(b, base)
	ip := net.ParseIP("203.0.113.10")
	eventTime := base.Add(30 * time.Second)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if result := correlator.Lookup(ip, 9999, eventTime); result == nil {
			b.Fatal("Lookup() = nil")
		}
	}
}

func BenchmarkDNSCorrelationLookupPIDSpecific(b *testing.B) {
	base := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	correlator := benchmarkDNSCorrelator(b, base)
	ip := net.ParseIP("203.0.113.10")
	eventTime := base.Add(30 * time.Second)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if result := correlator.Lookup(ip, 4242, eventTime); result == nil {
			b.Fatal("Lookup() = nil")
		}
	}
}

func benchmarkDNSCorrelator(b *testing.B, base time.Time) *dnsCorrelator {
	b.Helper()

	pid := uint32(4242)
	correlator := newDNSCorrelator()
	observations := make([]dnsObservation, 0, 34)

	for index := 0; index < 32; index++ {
		observations = append(observations, dnsObservation{
			IP:         "203.0.113.10",
			Name:       "shared.example",
			Source:     "benchmark",
			ObservedAt: base.Add(time.Duration(index) * time.Millisecond),
			ExpiresAt:  base.Add(time.Minute),
		})
	}

	observations = append(observations,
		dnsObservation{
			IP:         "203.0.113.10",
			Name:       "pid.example",
			Source:     "benchmark",
			ObservedAt: base.Add(time.Second),
			ExpiresAt:  base.Add(time.Minute),
			PID:        &pid,
		},
		dnsObservation{
			IP:         "2001:db8::10",
			Name:       "other.example",
			Source:     "benchmark",
			ObservedAt: base,
			ExpiresAt:  base.Add(time.Minute),
		},
	)

	if err := correlator.Add(observations); err != nil {
		b.Fatal(err)
	}

	return correlator
}
