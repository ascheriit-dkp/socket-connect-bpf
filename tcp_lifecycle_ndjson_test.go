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
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewTCPLifecycleNDJSONEvent(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(
		2026,
		time.August,
		18,
		9,
		30,
		0,
		123,
		time.UTC,
	)

	tests := []struct {
		name  string
		event tcpLifecycleEventPayload
		check func(*testing.T, tcpLifecycleNDJSONEvent)
	}{
		{
			name: "connect attempt preserves absent local endpoint",
			event: tcpLifecycleEventPayload{
				ObservedAt:        observedAt,
				EventType:         tcpLifecycleEventTypeConnectAttempt,
				Protocol:          "tcp",
				AddressFamily:     "AF_INET",
				ConnectionID:      42,
				KernelTimestampNS: 1_000,
				PID:               1234,
				UID:               1000,
				Comm:              "curl",
				Remote: tcpLifecycleEndpointPayload{
					IP:   net.ParseIP("198.51.100.20").To4(),
					Port: uint16Pointer(443),
				},
			},
			check: func(t *testing.T, got tcpLifecycleNDJSONEvent) {
				t.Helper()

				if got.Result != "" ||
					got.Local.IP != "" ||
					got.Local.Port != nil {
					t.Fatalf(
						"attempt event = %#v; want absent result and local endpoint",
						got,
					)
				}
			},
		},
		{
			name: "established",
			event: tcpLifecycleEventPayload{
				ObservedAt:        observedAt,
				EventType:         tcpLifecycleEventTypeEstablished,
				Protocol:          "tcp",
				AddressFamily:     "AF_INET6",
				ConnectionID:      84,
				KernelTimestampNS: 2_500,
				PID:               5678,
				UID:               1000,
				Comm:              "curl",
				Local: tcpLifecycleEndpointPayload{
					IP:   net.ParseIP("2001:db8::10").To16(),
					Port: uint16Pointer(40_001),
				},
				Remote: tcpLifecycleEndpointPayload{
					IP:   net.ParseIP("2001:db8::20").To16(),
					Port: uint16Pointer(8443),
				},
				ConnectLatencyNS: uint64Pointer(500),
			},
			check: func(t *testing.T, got tcpLifecycleNDJSONEvent) {
				t.Helper()

				if got.Result != tcpLifecycleResultSuccess {
					t.Fatalf(
						"result = %q; want %q",
						got.Result,
						tcpLifecycleResultSuccess,
					)
				}

				if got.ConnectLatencyNS == nil ||
					*got.ConnectLatencyNS != 500 {
					t.Fatalf(
						"connect latency = %v; want 500",
						got.ConnectLatencyNS,
					)
				}
			},
		},
		{
			name: "failed without errno",
			event: tcpLifecycleEventPayload{
				ObservedAt:        observedAt,
				EventType:         tcpLifecycleEventTypeConnectFailed,
				Protocol:          "tcp",
				AddressFamily:     "AF_INET",
				ConnectionID:      42,
				KernelTimestampNS: 1_250,
				PID:               1234,
				UID:               1000,
				Comm:              "curl",
				Remote: tcpLifecycleEndpointPayload{
					IP:   net.ParseIP("198.51.100.20").To4(),
					Port: uint16Pointer(443),
				},
				FailureSource:    "tcp_state",
				ConnectLatencyNS: uint64Pointer(250),
			},
			check: func(t *testing.T, got tcpLifecycleNDJSONEvent) {
				t.Helper()

				if got.Result != tcpLifecycleResultFailed {
					t.Fatalf(
						"result = %q; want %q",
						got.Result,
						tcpLifecycleResultFailed,
					)
				}

				if got.FailureSource != "tcp_state" ||
					got.Errno != nil ||
					got.Error != "" {
					t.Fatalf(
						"failure fields = %#v; want source without errno",
						got,
					)
				}
			},
		},
		{
			name: "closed",
			event: tcpLifecycleEventPayload{
				ObservedAt:           observedAt,
				EventType:            tcpLifecycleEventTypeClosed,
				Protocol:             "tcp",
				AddressFamily:        "AF_INET",
				ConnectionID:         42,
				KernelTimestampNS:    3_000,
				PID:                  1234,
				UID:                  1000,
				Comm:                 "curl",
				ConnectionDurationNS: uint64Pointer(1_500),
			},
			check: func(t *testing.T, got tcpLifecycleNDJSONEvent) {
				t.Helper()

				if got.Result != "" ||
					got.ConnectionDurationNS == nil ||
					*got.ConnectionDurationNS != 1_500 {
					t.Fatalf(
						"closed event = %#v; want duration without result",
						got,
					)
				}
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := newTCPLifecycleNDJSONEvent(test.event)
			if err != nil {
				t.Fatalf("building NDJSON event: %v", err)
			}

			if got.SchemaVersion != tcpLifecycleOutputSchemaVersion ||
				got.EventType != test.event.EventType ||
				got.ConnectionID != test.event.ConnectionID ||
				got.ObservedAt != observedAt.Format(time.RFC3339Nano) ||
				got.KernelTimestampNS != test.event.KernelTimestampNS ||
				got.Protocol != test.event.Protocol ||
				got.AddressFamily != test.event.AddressFamily ||
				got.Process.PID != test.event.PID ||
				got.Process.UID != test.event.UID ||
				got.Process.Comm != test.event.Comm {
				t.Fatalf(
					"common NDJSON fields = %#v; event = %#v",
					got,
					test.event,
				)
			}

			test.check(t, got)
		})
	}
}

func TestTCPLifecycleNDJSONPreservesPresentZeroPort(t *testing.T) {
	t.Parallel()

	event := tcpLifecycleEventPayload{
		ObservedAt:        time.Unix(0, 0).UTC(),
		EventType:         tcpLifecycleEventTypeConnectAttempt,
		Protocol:          "tcp",
		AddressFamily:     "AF_INET",
		ConnectionID:      42,
		KernelTimestampNS: 1_000,
		PID:               1234,
		UID:               1000,
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("198.51.100.20").To4(),
			Port: uint16Pointer(0),
		},
	}

	var buffer bytes.Buffer
	output := newTCPLifecycleNDJSONOutputWithWriter(&buffer)

	if err := output.WriteEvent(event); err != nil {
		t.Fatalf("writing NDJSON event: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding written JSON: %v", err)
	}

	remote, ok := decoded["remote"].(map[string]any)
	if !ok {
		t.Fatalf("remote = %#v; want object", decoded["remote"])
	}

	port, ok := remote["port"]
	if !ok {
		t.Fatal("remote port omitted; want present zero value")
	}

	if port != float64(0) {
		t.Fatalf("remote port = %#v; want 0", port)
	}
}

func TestNewTCPLifecycleNDJSONEventRejectsUnsupportedType(t *testing.T) {
	t.Parallel()

	got, err := newTCPLifecycleNDJSONEvent(tcpLifecycleEventPayload{
		EventType: "unsupported",
	})
	if err == nil {
		t.Fatal("building NDJSON event succeeded; want an error")
	}

	if !strings.Contains(err.Error(), "unsupported event type") {
		t.Fatalf(
			"error = %q; want unsupported event type detail",
			err,
		)
	}

	if got.EventType != "" || got.SchemaVersion != 0 {
		t.Fatalf("event = %#v; want zero value", got)
	}
}
