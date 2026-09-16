package main

import (
	"net"
	"testing"
	"time"
)

func TestTCPLifecycleNDJSONIncludesDNSCorrelation(t *testing.T) {
	observedAt := time.Date(2026, 9, 16, 8, 0, 2, 0, time.UTC)
	expiresAt := observedAt.Add(time.Minute)

	event := tcpLifecycleEventPayload{
		ObservedAt:        observedAt,
		EventType:         tcpLifecycleEventTypeConnectAttempt,
		Protocol:          tcpLifecycleProtocolTCP,
		AddressFamily:     "AF_INET",
		ConnectionID:      1,
		KernelTimestampNS: 10,
		PID:               42,
		UID:               1000,
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("203.0.113.10"),
			Port: uint16Pointer(443),
		},
		DNS: &dnsCorrelationPayload{
			Name:       "api.example",
			Source:     "resolver-log",
			Confidence: dnsConfidenceHigh,
			ObservedAt: observedAt.Add(-time.Second),
			ExpiresAt:  expiresAt,
		},
	}

	got, err := newTCPLifecycleNDJSONEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if got.DNS == nil {
		t.Fatal("DNS = nil")
	}
	if got.DNS.Name != "api.example" || got.DNS.Confidence != dnsConfidenceHigh {
		t.Fatalf("DNS = %#v", got.DNS)
	}
}

func TestUDPNDJSONIncludesDNSCorrelation(t *testing.T) {
	observedAt := time.Date(2026, 9, 16, 8, 0, 2, 0, time.UTC)
	event := udpEventPayload{
		ObservedAt:        observedAt,
		EventType:         udpEventTypeSend,
		Protocol:          udpProtocol,
		AddressFamily:     "AF_INET6",
		KernelTimestampNS: 20,
		PID:               43,
		UID:               1000,
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("2001:db8::10"),
			Port: uint16Pointer(53),
		},
		DNS: &dnsCorrelationPayload{
			Name:       "dns.example",
			Source:     "resolver-log",
			Confidence: dnsConfidenceMedium,
			ObservedAt: observedAt.Add(-time.Second),
			ExpiresAt:  observedAt.Add(time.Minute),
		},
	}

	got := newUDPNDJSONEvent(event)
	if got.DNS == nil {
		t.Fatal("DNS = nil")
	}
	if got.DNS.Name != "dns.example" || got.DNS.Confidence != dnsConfidenceMedium {
		t.Fatalf("DNS = %#v", got.DNS)
	}
}

func TestDNSCorrelationOmittedWhenAbsent(t *testing.T) {
	tcpEvent := tcpLifecycleEventPayload{
		ObservedAt:        time.Now(),
		EventType:         tcpLifecycleEventTypeConnectAttempt,
		Protocol:          tcpLifecycleProtocolTCP,
		AddressFamily:     "AF_INET",
		ConnectionID:      1,
		KernelTimestampNS: 1,
		PID:               1,
		UID:               1,
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("203.0.113.1"),
			Port: uint16Pointer(443),
		},
	}
	encoded, err := newTCPLifecycleNDJSONEvent(tcpEvent)
	if err != nil {
		t.Fatal(err)
	}
	if encoded.DNS != nil {
		t.Fatalf("TCP DNS = %#v, want nil", encoded.DNS)
	}

	udpEvent := udpEventPayload{
		ObservedAt:        time.Now(),
		EventType:         udpEventTypeSend,
		Protocol:          udpProtocol,
		AddressFamily:     "AF_INET",
		KernelTimestampNS: 2,
		PID:               2,
		UID:               2,
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("203.0.113.2"),
			Port: uint16Pointer(53),
		},
	}
	udpEncoded := newUDPNDJSONEvent(udpEvent)
	if udpEncoded.DNS != nil {
		t.Fatalf("UDP DNS = %#v, want nil", udpEncoded.DNS)
	}
}
