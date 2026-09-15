// Copyright 2026 Ascheriit-Dkp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPLifecycleTableOutput(t *testing.T) {
	t.Parallel()

	connectLatency := uint64(500)
	localPort := uint16(40_000)
	remotePort := uint16(443)

	event := tcpLifecycleEventPayload{
		ObservedAt:           time.Date(2026, time.August, 18, 12, 0, 1, 0, time.UTC),
		EventType:            tcpLifecycleEventTypeEstablished,
		PID:                  1234,
		Comm:                 "curl\n\x1b[31m",
		Local:                tcpLifecycleEndpointPayload{IP: net.ParseIP("192.0.2.10").To4(), Port: &localPort},
		Remote:               tcpLifecycleEndpointPayload{IP: net.ParseIP("198.51.100.20").To4(), Port: &remotePort},
		ConnectLatencyNS:     &connectLatency,
		ConnectionDurationNS: nil,
	}

	var buffer bytes.Buffer
	output := newTCPLifecycleTableOutputWithWriter(&buffer)

	if err := output.PrintHeader(); err != nil {
		t.Fatalf("printing header: %v", err)
	}

	if err := output.WriteEvent(event); err != nil {
		t.Fatalf("writing event: %v", err)
	}

	got := buffer.String()
	for _, want := range []string{
		"TIME",
		"EVENT",
		"CONNECT_NS",
		"12:00:01",
		tcpLifecycleEventTypeEstablished,
		"curl\\n\\u001B[31m",
		"192.0.2.10:40000",
		"198.51.100.20:443",
		tcpLifecycleResultSuccess,
		"500",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("table output = %q; want text %q", got, want)
		}
	}

	if strings.Contains(got, "\x1b") {
		t.Fatalf("table output contains a raw escape character: %q", got)
	}
}

func TestTCPLifecycleTableOutputPreservesOptionalEndpointsAndZeroPort(
	t *testing.T,
) {
	t.Parallel()

	zeroPort := uint16(0)
	event := tcpLifecycleEventPayload{
		ObservedAt: time.Unix(0, 0).UTC(),
		EventType:  tcpLifecycleEventTypeConnectAttempt,
		PID:        1234,
		Comm:       "curl",
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("198.51.100.20").To4(),
			Port: &zeroPort,
		},
	}

	var buffer bytes.Buffer
	output := newTCPLifecycleTableOutputWithWriter(&buffer)

	if err := output.WriteEvent(event); err != nil {
		t.Fatalf("writing event: %v", err)
	}

	got := buffer.String()
	if !strings.Contains(got, "198.51.100.20:0") {
		t.Fatalf("table output = %q; want present zero port", got)
	}

	if !strings.Contains(got, " - ") {
		t.Fatalf("table output = %q; want absent local endpoint marker", got)
	}
}

func TestFormatTCPLifecycleTableEndpointIPv6(t *testing.T) {
	t.Parallel()

	port := uint16(8443)
	got := formatTCPLifecycleTableEndpoint(tcpLifecycleEndpointPayload{
		IP:   net.ParseIP("2001:db8::20").To16(),
		Port: &port,
	})

	if got != "[2001:db8::20]:8443" {
		t.Fatalf("endpoint = %q; want %q", got, "[2001:db8::20]:8443")
	}
}

func TestTCPLifecycleTableOutputRejectsUnsupportedType(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	output := newTCPLifecycleTableOutputWithWriter(&buffer)

	err := output.WriteEvent(tcpLifecycleEventPayload{
		EventType: "unsupported",
	})
	if err == nil {
		t.Fatal("writing event succeeded; want an error")
	}

	if !strings.Contains(err.Error(), "unsupported event type") {
		t.Fatalf("error = %q; want unsupported event type detail", err)
	}

	if buffer.Len() != 0 {
		t.Fatalf("buffer = %q; want no output", buffer.String())
	}
}
