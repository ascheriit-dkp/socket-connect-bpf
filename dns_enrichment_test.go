package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type dnsResolverFunc func(context.Context, string) ([]string, error)

func (function dnsResolverFunc) LookupAddr(
	ctx context.Context,
	address string,
) ([]string, error) {
	return function(ctx, address)
}

func TestDNSCorrelatorNormalizesAndCachesLookup(t *testing.T) {
	calls := 0
	now := time.Unix(100, 0)
	correlator := newDNSCorrelator(
		4,
		time.Second,
		time.Minute,
		time.Second,
		dnsResolverFunc(func(context.Context, string) ([]string, error) {
			calls++
			return []string{" Example.COM. "}, nil
		}),
		func() time.Time { return now },
	)

	first := correlator.Lookup(net.ParseIP("192.0.2.10"))
	second := correlator.Lookup(net.ParseIP("192.0.2.10"))

	if calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls)
	}
	if first == nil || second == nil {
		t.Fatal("Lookup() returned nil, want DNS correlation")
	}
	if first.Name != "example.com" {
		t.Fatalf("Name = %q, want example.com", first.Name)
	}
	if first.Source != dnsCorrelationSourceReverseDNS {
		t.Fatalf("Source = %q", first.Source)
	}
	if first.Confidence != dnsCorrelationConfidenceLow {
		t.Fatalf("Confidence = %q", first.Confidence)
	}
	if first == second {
		t.Fatal("cached Lookup() returned shared payload pointer")
	}
}

func TestDNSCorrelatorNegativeCacheExpires(t *testing.T) {
	calls := 0
	now := time.Unix(200, 0)
	correlator := newDNSCorrelator(
		4,
		time.Second,
		time.Minute,
		5*time.Second,
		dnsResolverFunc(func(context.Context, string) ([]string, error) {
			calls++
			return nil, errors.New("no PTR")
		}),
		func() time.Time { return now },
	)

	if got := correlator.Lookup(net.ParseIP("192.0.2.20")); got != nil {
		t.Fatalf("Lookup() = %#v, want nil", got)
	}
	if got := correlator.Lookup(net.ParseIP("192.0.2.20")); got != nil {
		t.Fatalf("cached Lookup() = %#v, want nil", got)
	}
	if calls != 1 {
		t.Fatalf("resolver calls before expiry = %d, want 1", calls)
	}

	now = now.Add(6 * time.Second)
	correlator.Lookup(net.ParseIP("192.0.2.20"))
	if calls != 2 {
		t.Fatalf("resolver calls after expiry = %d, want 2", calls)
	}
}

func TestDNSCorrelatorEvictsLeastRecentlyUsedEntry(t *testing.T) {
	calls := make(map[string]int)
	correlator := newDNSCorrelator(
		2,
		time.Second,
		time.Minute,
		time.Second,
		dnsResolverFunc(func(_ context.Context, address string) ([]string, error) {
			calls[address]++
			return []string{address + ".example."}, nil
		}),
		time.Now,
	)

	first := net.ParseIP("192.0.2.1")
	second := net.ParseIP("192.0.2.2")
	third := net.ParseIP("192.0.2.3")

	correlator.Lookup(first)
	correlator.Lookup(second)
	correlator.Lookup(first)
	correlator.Lookup(third)
	correlator.Lookup(second)

	if calls[first.String()] != 1 {
		t.Fatalf("first resolver calls = %d, want 1", calls[first.String()])
	}
	if calls[second.String()] != 2 {
		t.Fatalf("second resolver calls = %d, want 2 after eviction", calls[second.String()])
	}
}

func TestDNSCorrelatorBoundsResolverWait(t *testing.T) {
	correlator := newDNSCorrelator(
		1,
		10*time.Millisecond,
		time.Minute,
		time.Second,
		dnsResolverFunc(func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
		time.Now,
	)

	started := time.Now()
	if got := correlator.Lookup(net.ParseIP("192.0.2.30")); got != nil {
		t.Fatalf("Lookup() = %#v, want nil", got)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Lookup() took %s, timeout was not bounded", elapsed)
	}
}

func TestNormalizeDNSCorrelationSkipsEmptyNames(t *testing.T) {
	got := normalizeDNSCorrelation([]string{".", " example.net. "}, nil)
	if got == nil || got.Name != "example.net" {
		t.Fatalf("normalizeDNSCorrelation() = %#v", got)
	}

	if got := normalizeDNSCorrelation(nil, nil); got != nil {
		t.Fatalf("normalizeDNSCorrelation(nil) = %#v, want nil", got)
	}
}
