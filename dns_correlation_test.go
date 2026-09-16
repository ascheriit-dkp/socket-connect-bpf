package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDNSCorrelatorPrefersPIDSpecificObservation(t *testing.T) {
	observedAt := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	pid := uint32(4242)
	correlator := newDNSCorrelator()

	if err := correlator.Add([]dnsObservation{
		{
			IP:         "203.0.113.10",
			Name:       "shared.example",
			Source:     "resolver-log",
			ObservedAt: observedAt,
			ExpiresAt:  observedAt.Add(time.Minute),
		},
		{
			IP:         "203.0.113.10",
			Name:       "pid.example",
			Source:     "resolver-log",
			ObservedAt: observedAt.Add(time.Second),
			ExpiresAt:  observedAt.Add(time.Minute),
			PID:        &pid,
		},
	}); err != nil {
		t.Fatal(err)
	}

	got := correlator.Lookup(
		net.ParseIP("203.0.113.10"),
		pid,
		observedAt.Add(2*time.Second),
	)
	if got == nil {
		t.Fatal("Lookup() = nil")
	}
	if got.Name != "pid.example" {
		t.Fatalf("Name = %q, want pid.example", got.Name)
	}
	if got.Confidence != dnsConfidenceHigh {
		t.Fatalf("Confidence = %q, want %q", got.Confidence, dnsConfidenceHigh)
	}
}

func TestDNSCorrelatorUsesGlobalObservationAtMediumConfidence(t *testing.T) {
	observedAt := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	correlator := newDNSCorrelator()
	if err := correlator.Add([]dnsObservation{{
		IP:         "2001:db8::10",
		Name:       "global.example",
		Source:     "dnsmasq",
		ObservedAt: observedAt,
		ExpiresAt:  observedAt.Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}

	got := correlator.Lookup(
		net.ParseIP("2001:db8::10"),
		99,
		observedAt.Add(time.Second),
	)
	if got == nil {
		t.Fatal("Lookup() = nil")
	}
	if got.Confidence != dnsConfidenceMedium {
		t.Fatalf("Confidence = %q, want %q", got.Confidence, dnsConfidenceMedium)
	}
	if got.Source != "dnsmasq" {
		t.Fatalf("Source = %q, want dnsmasq", got.Source)
	}
}

func TestDNSCorrelatorRejectsExpiredFutureAndOtherPID(t *testing.T) {
	base := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	otherPID := uint32(7)
	correlator := newDNSCorrelator()
	if err := correlator.Add([]dnsObservation{
		{
			IP:         "198.51.100.20",
			Name:       "expired.example",
			Source:     "test",
			ObservedAt: base,
			ExpiresAt:  base.Add(time.Second),
		},
		{
			IP:         "198.51.100.20",
			Name:       "future.example",
			Source:     "test",
			ObservedAt: base.Add(10 * time.Second),
			ExpiresAt:  base.Add(time.Minute),
		},
		{
			IP:         "198.51.100.20",
			Name:       "other-pid.example",
			Source:     "test",
			ObservedAt: base,
			ExpiresAt:  base.Add(time.Minute),
			PID:        &otherPID,
		},
	}); err != nil {
		t.Fatal(err)
	}

	got := correlator.Lookup(
		net.ParseIP("198.51.100.20"),
		42,
		base.Add(5*time.Second),
	)
	if got != nil {
		t.Fatalf("Lookup() = %#v, want nil", got)
	}
}

func TestLoadDNSObservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.jsonl")
	content := strings.Join([]string{
		"# generated fixture",
		`{"ip":"203.0.113.7","name":"api.example.","observed_at":"2026-09-16T08:00:00Z","ttl_seconds":60,"pid":123,"source":"resolver-log"}`,
		`{"ip":"2001:db8::7","name":"v6.example","observed_at":"2026-09-16T08:00:01Z","ttl_seconds":120}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	observations, err := loadDNSObservations(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 {
		t.Fatalf("len(observations) = %d, want 2", len(observations))
	}
	if observations[0].Name != "api.example" {
		t.Fatalf("first name = %q, want api.example", observations[0].Name)
	}
	if observations[1].Source != defaultDNSObservationSource {
		t.Fatalf(
			"second source = %q, want %q",
			observations[1].Source,
			defaultDNSObservationSource,
		)
	}
}

func TestLoadDNSObservationsRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		contains string
	}{
		{
			name:     "invalid IP",
			record:   `{"ip":"nope","name":"x.example","observed_at":"2026-09-16T08:00:00Z","ttl_seconds":60}`,
			contains: "invalid IP",
		},
		{
			name:     "zero TTL",
			record:   `{"ip":"203.0.113.1","name":"x.example","observed_at":"2026-09-16T08:00:00Z","ttl_seconds":0}`,
			contains: "ttl_seconds",
		},
		{
			name:     "unknown field",
			record:   `{"ip":"203.0.113.1","name":"x.example","observed_at":"2026-09-16T08:00:00Z","ttl_seconds":60,"extra":true}`,
			contains: "unknown field",
		},
		{
			name:     "trailing JSON",
			record:   `{"ip":"203.0.113.1","name":"x.example","observed_at":"2026-09-16T08:00:00Z","ttl_seconds":60} {"extra":true}`,
			contains: "trailing data",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dns.jsonl")
			if err := os.WriteFile(
				path,
				[]byte(test.record+"\n"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			_, err := loadDNSObservations(path)
			if err == nil {
				t.Fatal("loadDNSObservations() error = nil")
			}
			if !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %q, want substring %q", err, test.contains)
			}
		})
	}
}

func TestDNSObservationFileFlagLoadsData(t *testing.T) {
	original := activeDNSCorrelator
	activeDNSCorrelator = newDNSCorrelator()
	t.Cleanup(func() {
		activeDNSCorrelator = original
	})

	path := filepath.Join(t.TempDir(), "dns.jsonl")
	content := fmt.Sprintf(
		"{\"ip\":\"203.0.113.8\",\"name\":\"flag.example\",\"observed_at\":\"%s\",\"ttl_seconds\":60}\n",
		time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC).Format(time.RFC3339),
	)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	values := &dnsObservationFileValues{}
	if err := values.Set(path); err != nil {
		t.Fatal(err)
	}
	if len(*values) != 1 || (*values)[0] != path {
		t.Fatalf("values = %#v", *values)
	}

	got := activeDNSCorrelator.Lookup(
		net.ParseIP("203.0.113.8"),
		1,
		time.Date(2026, 9, 16, 8, 0, 1, 0, time.UTC),
	)
	if got == nil || got.Name != "flag.example" {
		t.Fatalf("Lookup() = %#v", got)
	}
}
