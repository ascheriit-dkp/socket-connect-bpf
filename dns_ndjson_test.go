package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestTCPLifecycleNDJSONAddsDNSCorrelation(t *testing.T) {
	restoreDNSFixture(t, "tcp.example.")

	event := tcpLifecycleNDJSONEvent{
		SchemaVersion: tcpLifecycleOutputSchemaVersion,
		EventType:     tcpLifecycleEventTypeConnectAttempt,
		Remote: tcpLifecycleNDJSONEndpoint{
			IP: "192.0.2.40",
		},
	}

	assertDNSMetadata(t, event)
}

func TestUDPNDJSONAddsDNSCorrelation(t *testing.T) {
	restoreDNSFixture(t, "udp.example.")

	event := udpNDJSONEvent{
		SchemaVersion: udpOutputSchemaVersion,
		EventType:     udpEventTypeSend,
		Remote: tcpLifecycleNDJSONEndpoint{
			IP: "192.0.2.41",
		},
	}

	assertDNSMetadata(t, event)
}

func TestNDJSONOmitsDNSWhenDisabled(t *testing.T) {
	originalEnabled := *dnsEnrichmentFlag
	*dnsEnrichmentFlag = false
	t.Cleanup(func() {
		*dnsEnrichmentFlag = originalEnabled
	})

	event := tcpLifecycleNDJSONEvent{
		SchemaVersion: tcpLifecycleOutputSchemaVersion,
		Remote: tcpLifecycleNDJSONEndpoint{
			IP: "192.0.2.42",
		},
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["dns"]; ok {
		t.Fatalf("disabled DNS field present in %s", encoded)
	}
}

func restoreDNSFixture(t *testing.T, name string) {
	t.Helper()

	originalEnabled := *dnsEnrichmentFlag
	originalCorrelator := defaultDNSCorrelator
	*dnsEnrichmentFlag = true
	defaultDNSCorrelator = newDNSCorrelator(
		4,
		time.Second,
		time.Minute,
		time.Second,
		dnsResolverFunc(func(context.Context, string) ([]string, error) {
			return []string{name}, nil
		}),
		time.Now,
	)

	t.Cleanup(func() {
		*dnsEnrichmentFlag = originalEnabled
		defaultDNSCorrelator = originalCorrelator
	})
}

func assertDNSMetadata(t *testing.T, event any) {
	t.Helper()

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		DNS *dnsNDJSONPayload `json:"dns"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.DNS == nil {
		t.Fatalf("DNS metadata missing from %s", encoded)
	}
	if decoded.DNS.Source != dnsCorrelationSourceReverseDNS {
		t.Fatalf("DNS source = %q", decoded.DNS.Source)
	}
	if decoded.DNS.Confidence != dnsCorrelationConfidenceLow {
		t.Fatalf("DNS confidence = %q", decoded.DNS.Confidence)
	}
}
