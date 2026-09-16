package main

import (
	"net"
	"strings"
	"testing"
)

func TestTCPLifecycleTableRemoteIncludesDNSMetadata(t *testing.T) {
	restoreDNSFixture(t, "tcp-table.example.")
	port := uint16(443)

	got := formatTCPLifecycleTableRemote(tcpLifecycleEndpointPayload{
		IP:   net.ParseIP("192.0.2.50"),
		Port: &port,
	})

	if !strings.Contains(got, "tcp-table.example [reverse_dns/low]") {
		t.Fatalf("formatted remote = %q", got)
	}
}

func TestUDPTableRemoteIncludesDNSMetadata(t *testing.T) {
	restoreDNSFixture(t, "udp-table.example.")
	port := uint16(53)

	got := formatUDPRemote(tcpLifecycleEndpointPayload{
		IP:   net.ParseIP("192.0.2.51"),
		Port: &port,
	})

	if !strings.Contains(got, "udp-table.example [reverse_dns/low]") {
		t.Fatalf("formatted remote = %q", got)
	}
}
