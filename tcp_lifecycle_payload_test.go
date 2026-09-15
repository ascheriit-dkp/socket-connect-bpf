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
	"strings"
	"testing"
	"time"

	"github.com/ascheriit-dkp/socket-connect-bpf/conv"
	"golang.org/x/sys/unix"
)

func TestNewTCPLifecycleEventPayload(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(
		2026,
		time.August,
		5,
		14,
		30,
		0,
		123,
		time.UTC,
	)

	tests := []struct {
		name                   string
		event                  kernelTCPLifecycleEvent
		wantEventType          string
		wantEstablishedNS      *uint64
		wantFailureSource      string
		wantErrno              *int32
		wantConnectLatencyNS   *uint64
		wantConnectionDuration *uint64
	}{
		{
			name:          "attempt",
			event:         validIPv4TCPLifecycleAttempt(),
			wantEventType: tcpLifecycleEventTypeConnectAttempt,
		},
		{
			name:          "IPv6 attempt",
			event:         validIPv6TCPLifecycleAttempt(),
			wantEventType: tcpLifecycleEventTypeConnectAttempt,
		},
		{
			name: "established",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType = kernelTCPLifecycleEventTypeEstablished
				event.KernelTimestampNS = 1_500
				event.EstablishedTimestampNS = 1_500

				return event
			}(),
			wantEventType:        tcpLifecycleEventTypeEstablished,
			wantEstablishedNS:    uint64Pointer(1_500),
			wantConnectLatencyNS: uint64Pointer(500),
		},
		{
			name: "failed with errno",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType = kernelTCPLifecycleEventTypeConnectFailed
				event.KernelTimestampNS = 1_250
				event.FailureSource =
					kernelTCPLifecycleFailureSourceConnectReturn
				event.Flags |= kernelTCPLifecycleFlagErrorCode
				event.ErrorCode = int32(unix.ECONNREFUSED)

				return event
			}(),
			wantEventType:        tcpLifecycleEventTypeConnectFailed,
			wantFailureSource:    tcpLifecycleFailureSourceConnectReturn,
			wantErrno:            int32Pointer(int32(unix.ECONNREFUSED)),
			wantConnectLatencyNS: uint64Pointer(250),
		},
		{
			name: "closed",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType = kernelTCPLifecycleEventTypeClosed
				event.KernelTimestampNS = 3_000
				event.EstablishedTimestampNS = 1_500

				return event
			}(),
			wantEventType:          tcpLifecycleEventTypeClosed,
			wantEstablishedNS:      uint64Pointer(1_500),
			wantConnectionDuration: uint64Pointer(1_500),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := newTCPLifecycleEventPayload(
				test.event,
				observedAt,
			)
			if err != nil {
				t.Fatalf("building payload: %v", err)
			}

			assertTCPLifecyclePayloadCommonFields(
				t,
				got,
				test.event,
				observedAt,
			)

			if got.EventType != test.wantEventType {
				t.Fatalf(
					"event type = %q; want %q",
					got.EventType,
					test.wantEventType,
				)
			}

			assertOptionalUint64(
				t,
				"established timestamp",
				got.EstablishedTimestampNS,
				test.wantEstablishedNS,
			)
			assertOptionalUint64(
				t,
				"connect latency",
				got.ConnectLatencyNS,
				test.wantConnectLatencyNS,
			)
			assertOptionalUint64(
				t,
				"connection duration",
				got.ConnectionDurationNS,
				test.wantConnectionDuration,
			)

			if got.FailureSource != test.wantFailureSource {
				t.Fatalf(
					"failure source = %q; want %q",
					got.FailureSource,
					test.wantFailureSource,
				)
			}

			assertOptionalInt32(
				t,
				"errno",
				got.Errno,
				test.wantErrno,
			)

			if test.wantErrno == nil {
				if got.Error != "" {
					t.Fatalf(
						"error text = %q; want empty",
						got.Error,
					)
				}
			} else {
				wantError := unix.Errno(*test.wantErrno).Error()
				if got.Error != wantError {
					t.Fatalf(
						"error text = %q; want %q",
						got.Error,
						wantError,
					)
				}
			}
		})
	}
}

func TestNewTCPLifecycleEventPayloadPreservesAbsentLocalEndpoint(
	t *testing.T,
) {
	t.Parallel()

	event := validIPv4TCPLifecycleAttempt()
	event.Flags &^= kernelTCPLifecycleFlagLocalAddress |
		kernelTCPLifecycleFlagLocalPort
	event.LocalAddressLength = kernelAddressLengthNone
	event.LocalAddress = [16]byte{}
	event.LocalPort = 0

	got, err := newTCPLifecycleEventPayload(event, time.Now())
	if err != nil {
		t.Fatalf("building payload: %v", err)
	}

	if got.Local.IP != nil {
		t.Fatalf("local IP = %v; want nil", got.Local.IP)
	}

	if got.Local.Port != nil {
		t.Fatalf("local port = %d; want nil", *got.Local.Port)
	}
}

func TestNewTCPLifecycleEventPayloadRejectsInvalidEvent(t *testing.T) {
	t.Parallel()

	event := validIPv4TCPLifecycleAttempt()
	event.ConnectionID = 0

	got, err := newTCPLifecycleEventPayload(event, time.Now())
	if err == nil {
		t.Fatal("building payload succeeded; want an error")
	}

	if !strings.Contains(err.Error(), "build TCP lifecycle payload") {
		t.Fatalf("error = %q; want payload context", err)
	}

	if !strings.Contains(err.Error(), "connection ID zero") {
		t.Fatalf("error = %q; want validation detail", err)
	}

	if got.EventType != "" || got.ConnectionID != 0 {
		t.Fatalf("payload = %#v; want zero value", got)
	}
}

func assertTCPLifecyclePayloadCommonFields(
	t *testing.T,
	got tcpLifecycleEventPayload,
	event kernelTCPLifecycleEvent,
	observedAt time.Time,
) {
	t.Helper()

	if !got.ObservedAt.Equal(observedAt) {
		t.Fatalf(
			"observed time = %s; want %s",
			got.ObservedAt,
			observedAt,
		)
	}

	if got.Protocol != tcpLifecycleProtocolTCP {
		t.Fatalf(
			"protocol = %q; want %q",
			got.Protocol,
			tcpLifecycleProtocolTCP,
		)
	}

	wantAddressFamily := conv.ToAddressFamily(int(event.AddressFamily))
	if got.AddressFamily != wantAddressFamily {
		t.Fatalf(
			"address family = %q; want %q",
			got.AddressFamily,
			wantAddressFamily,
		)
	}

	if got.ConnectionID != event.ConnectionID ||
		got.KernelTimestampNS != event.KernelTimestampNS ||
		got.AttemptTimestampNS != event.AttemptTimestampNS ||
		got.PID != event.PID ||
		got.UID != event.UID ||
		got.Comm != "curl" {
		t.Fatalf(
			"payload metadata = %#v; event = %#v",
			got,
			event,
		)
	}

	if !got.Local.IP.Equal(event.localIP()) {
		t.Fatalf(
			"local IP = %v; want %v",
			got.Local.IP,
			event.localIP(),
		)
	}

	if !got.Remote.IP.Equal(event.remoteIP()) {
		t.Fatalf(
			"remote IP = %v; want %v",
			got.Remote.IP,
			event.remoteIP(),
		)
	}

	if got.Local.Port == nil || *got.Local.Port != event.LocalPort {
		t.Fatalf(
			"local port = %v; want %d",
			got.Local.Port,
			event.LocalPort,
		)
	}

	if got.Remote.Port == nil || *got.Remote.Port != event.RemotePort {
		t.Fatalf(
			"remote port = %v; want %d",
			got.Remote.Port,
			event.RemotePort,
		)
	}
}

func assertOptionalUint64(
	t *testing.T,
	name string,
	got *uint64,
	want *uint64,
) {
	t.Helper()

	if got == nil || want == nil {
		if got != nil || want != nil {
			t.Fatalf(
				"%s = %v; want %v",
				name,
				got,
				want,
			)
		}

		return
	}

	if *got != *want {
		t.Fatalf(
			"%s = %d; want %d",
			name,
			*got,
			*want,
		)
	}
}

func assertOptionalInt32(
	t *testing.T,
	name string,
	got *int32,
	want *int32,
) {
	t.Helper()

	if got == nil || want == nil {
		if got != nil || want != nil {
			t.Fatalf(
				"%s = %v; want %v",
				name,
				got,
				want,
			)
		}

		return
	}

	if *got != *want {
		t.Fatalf(
			"%s = %d; want %d",
			name,
			*got,
			*want,
		)
	}
}
