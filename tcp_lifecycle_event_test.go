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
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestKernelTCPLifecycleEventLayout(t *testing.T) {
	t.Parallel()

	var event kernelTCPLifecycleEvent

	if got := binary.Size(event); got != kernelTCPLifecycleEventBinarySize {
		t.Fatalf(
			"binary size = %d; want %d",
			got,
			kernelTCPLifecycleEventBinarySize,
		)
	}

	if got := int(unsafe.Sizeof(event)); got !=
		kernelTCPLifecycleEventBinarySize {
		t.Fatalf(
			"memory size = %d; want %d",
			got,
			kernelTCPLifecycleEventBinarySize,
		)
	}

	expectedOffsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{
			name: "
	}{
		{
			name: "ABIVersion",
			got:  unsafe.Offsetof(event.ABIVersion),
			want: 0,
		},
		{
			name: "EventType",
			got:  unsafe.Offsetof(event.EventType),
			want: 2,
		},
		{
			name: "Protocol",
			got:  unsafe.Offsetof(event.Protocol),
			want: 3,
		},
		{
			name: "AddressFamily",
			got:  unsafe.Offsetof(event.AddressFamily),
			want: 4,
		},
		{
			name: "Flags",
			got:  unsafe.Offsetof(event.Flags),
			want: 6,
		},
		{
			name: "PID",
			got:  unsafe.Offsetof(event.PID),
			want: 8,
		},
		{
			name: "UID",
			got:  unsafe.Offsetof(event.UID),
			want: 12,
		},
		{
			name: "ConnectionID",
			got:  unsafe.Offsetof(event.ConnectionID),
			want: 16,
		},
		{
			name: "KernelTimestampNS",
			got:  unsafe.Offsetof(event.KernelTimestampNS),
			want: 24,
		},
		{
			name: "AttemptTimestampNS",
			got:  unsafe.Offsetof(event.AttemptTimestampNS),
			want: 32,
		},
		{
			name: "EstablishedTimestampNS",
			got:  unsafe.Offsetof(event.EstablishedTimestampNS),
			want: 40,
		},
		{
			name: "ErrorCode",
			got:  unsafe.Offsetof(event.ErrorCode),
			want: 48,
		},
		{
			name: "FailureSource",
			got:  unsafe.Offsetof(event.FailureSource),
			want: 52,
		},
		{
			name: "LocalAddressLength",
			got:  unsafe.Offsetof(event.LocalAddressLength),
			want: 53,
		},
		{
			name: "RemoteAddressLength",
			got:  unsafe.Offsetof(event.RemoteAddressLength),
			want: 54,
		},
		{
			name: "Reserved0",
			got:  unsafe.Offsetof(event.Reserved0),
			want: 55,
		},
		{
			name: "LocalPort",
			got:  unsafe.Offsetof(event.LocalPort),
			want: 56,
		},
		{
			name: "RemotePort",
			got:  unsafe.Offsetof(event.RemotePort),
			want: 58,
		},
		{
			name: "LocalAddress",
			got:  unsafe.Offsetof(event.LocalAddress),
			want: 60,
		},
		{
			name: "RemoteAddress",
			got:  unsafe.Offsetof(event.RemoteAddress),
			want: 76,
		},
		{
			name: "Task",
			got:  unsafe.Offsetof(event.Task),
			want: 92,
		},
		{
			name: "Reserved",
			got:  unsafe.Offsetof(event.Reserved),
			want: 108,
		},
	}

	for _, expectedOffset := range expectedOffsets {
		expectedOffset := expectedOffset

		t.Run(expectedOffset.name, func(t *testing.T) {
			t.Parallel()

			if expectedOffset.got != expectedOffset.want {
				t.Fatalf(
					"offset = %d; want %d",
					expectedOffset.got,
					expectedOffset.want,
				)
			}
		})
	}
}

func TestKernelTCPLifecycleEventEndpointIPs(t *testing.T) {
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		event := validIPv4TCPLifecycleAttempt()

		localIP := event.localIP()
		if !localIP.Equal(net.ParseIP("192.0.2.10")) {
			t.Fatalf(
				"local IP = %v; want 192.0.2.10",
				localIP,
			)
		}

		remoteIP := event.remoteIP()
		if !remoteIP.Equal(net.ParseIP("198.51.100.20")) {
			t.Fatalf(
				"remote IP = %v; want 198.51.100.20",
				remoteIP,
			)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Parallel()

		event := validIPv6TCPLifecycleAttempt()

		localIP := event.localIP()
		if !localIP.Equal(net.ParseIP("2001:db8::10")) {
			t.Fatalf(
				"local IP = %v; want 2001:db8::10",
				localIP,
			)
		}

		remoteIP := event.remoteIP()
		if !remoteIP.Equal(net.ParseIP("2001:db8::20")) {
			t.Fatalf(
				"remote IP = %v; want 2001:db8::20",
				remoteIP,
			)
		}
	})

	t.Run("absent local endpoint", func(t *testing.T) {
		t.Parallel()

		event := validIPv4TCPLifecycleAttempt()
		event.Flags &^= kernelTCPLifecycleFlagLocalAddress
		event.LocalAddressLength = kernelAddressLengthNone
		event.LocalAddress = [net.IPv6len]byte{}

		if got := event.localIP(); got != nil {
			t.Fatalf("local IP = %v; want nil", got)
		}
	})
}

func TestKernelTCPLifecycleEventConnectLatency(t *testing.T) {
	t.Parallel()

	for _, eventType := range []uint8{
		kernelTCPLifecycleEventTypeEstablished,
		kernelTCPLifecycleEventTypeConnectFailed,
	} {
		eventType := eventType

		t.Run(
			lifecycleEventTypeTestName(eventType),
			func(t *testing.T) {
				t.Parallel()

				event := validIPv4TCPLifecycleAttempt()
				event.EventType = eventType
				event.KernelTimestampNS = 1_750

				if eventType ==
					kernelTCPLifecycleEventTypeEstablished {
					event.EstablishedTimestampNS = 1_750
				} else {
					event.FailureSource =
						kernelTCPLifecycleFailureSourceTCPState
				}

				got, ok := event.connectLatencyNS()
				if !ok {
					t.Fatal("connect latency was unavailable")
				}

				const want uint64 = 750
				if got != want {
					t.Fatalf(
						"connect latency = %d; want %d",
						got,
						want,
					)
				}
			},
		)
	}

	event := validIPv4TCPLifecycleAttempt()

	if got, ok := event.connectLatencyNS(); ok {
		t.Fatalf(
			"attempt latency = %d, true; want unavailable",
			got,
		)
	}
}

func TestKernelTCPLifecycleEventConnectionDuration(t *testing.T) {
	t.Parallel()

	event := validIPv4TCPLifecycleAttempt()
	event.EventType = kernelTCPLifecycleEventTypeClosed
	event.KernelTimestampNS = 5_000
	event.EstablishedTimestampNS = 2_000

	got, ok := event.connectionDurationNS()
	if !ok {
		t.Fatal("connection duration was unavailable")
	}

	const want uint64 = 3_000
	if got != want {
		t.Fatalf(
			"connection duration = %d; want %d",
			got,
			want,
		)
	}

	event.EventType = kernelTCPLifecycleEventTypeEstablished

	if got, ok := event.connectionDurationNS(); ok {
		t.Fatalf(
			"established duration = %d, true; want unavailable",
			got,
		)
	}
}

func TestValidateKernelTCPLifecycleEventAcceptsValidEvents(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name  string
		event kernelTCPLifecycleEvent
	}{
		{
			name:  "IPv4 attempt",
			event: validIPv4TCPLifecycleAttempt(),
		},
		{
			name:  "IPv6 attempt",
			event: validIPv6TCPLifecycleAttempt(),
		},
		{
			name: "established",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType =
					kernelTCPLifecycleEventTypeEstablished
				event.KernelTimestampNS = 1_500
				event.EstablishedTimestampNS = 1_500

				return event
			}(),
		},
		{
			name: "failed with errno",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType =
					kernelTCPLifecycleEventTypeConnectFailed
				event.KernelTimestampNS = 1_250
				event.Flags |=
					kernelTCPLifecycleFlagErrorCode
				event.ErrorCode = unix.ECONNREFUSED
				event.FailureSource =
					kernelTCPLifecycleFailureSourceSocketError

				return event
			}(),
		},
		{
			name: "failed without errno",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType =
					kernelTCPLifecycleEventTypeConnectFailed
				event.KernelTimestampNS = 1_250
				event.FailureSource =
					kernelTCPLifecycleFailureSourceTCPState

				return event
			}(),
		},
		{
			name: "closed",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType =
					kernelTCPLifecycleEventTypeClosed
				event.KernelTimestampNS = 3_000
				event.EstablishedTimestampNS = 1_500

				return event
			}(),
		},
		{
			name: "attempt without local endpoint",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.Flags &^=
					kernelTCPLifecycleFlagLocalAddress |
						kernelTCPLifecycleFlagLocalPort
				event.LocalAddressLength =
					kernelAddressLengthNone
				event.LocalAddress = [net.IPv6len]byte{}
				event.LocalPort = 0

				return event
			}(),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := validateKernelTCPLifecycleEvent(
				test.event,
			); err != nil {
				t.Fatalf("validating event: %v", err)
			}
		})
	}
}

func TestValidateKernelTCPLifecycleEventRejectsInvalidEvents(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(*kernelTCPLifecycleEvent)
		errorText   string
	}{
		{
			name: "ABI version",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.ABIVersion = 99
			},
			errorText: "unsupported TCP lifecycle event ABI version",
		},
		{
			name: "event type",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.EventType = 99
			},
			errorText: "unsupported TCP lifecycle event type",
		},
		{
			name: "protocol",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Protocol = unix.IPPROTO_UDP
			},
			errorText: "unsupported TCP lifecycle protocol",
		},
		{
			name: "address family",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.AddressFamily = unix.AF_UNIX
			},
			errorText: "unsupported TCP lifecycle address family",
		},
		{
			name: "unknown flags",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Flags |= 1 << 15
			},
			errorText: "unsupported TCP lifecycle flags",
		},
		{
			name: "PID zero",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.PID = 0
			},
			errorText: "PID zero",
		},
		{
			name: "connection ID zero",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.ConnectionID = 0
			},
			errorText: "connection ID zero",
		},
		{
			name: "kernel timestamp zero",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.KernelTimestampNS = 0
			},
			errorText: "kernel timestamp zero",
		},
		{
			name: "attempt timestamp zero",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.AttemptTimestampNS = 0
			},
			errorText: "attempt timestamp zero",
		},
		{
			name: "attempt timestamp after event",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.AttemptTimestampNS =
					event.KernelTimestampNS + 1
			},
			errorText: "is after event timestamp",
		},
		{
			name: "reserved byte",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Reserved0 = 1
			},
			errorText: "reserved byte is non-zero",
		},
		{
			name: "reserved bytes",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Reserved[0] = 1
			},
			errorText: "reserved bytes are non-zero",
		},
		{
			name: "missing remote address",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Flags &^=
					kernelTCPLifecycleFlagRemoteAddress
				event.RemoteAddressLength =
					kernelAddressLengthNone
				event.RemoteAddress = [net.IPv6len]byte{}
			},
			errorText: "has no remote address",
		},
		{
			name: "missing remote port",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Flags &^=
					kernelTCPLifecycleFlagRemotePort
				event.RemotePort = 0
			},
			errorText: "has no remote port",
		},
		{
			name: "IPv4 address length",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.RemoteAddressLength =
					kernelAddressLengthIPv6
			},
			errorText: "remote address length",
		},
		{
			name: "IPv4 address padding",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.RemoteAddress[net.IPv4len] = 1
			},
			errorText: "non-zero padding",
		},
		{
			name: "unflagged local address",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Flags &^=
					kernelTCPLifecycleFlagLocalAddress
			},
			errorText: "local address is absent but has length",
		},
		{
			name: "unflagged local port",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Flags &^=
					kernelTCPLifecycleFlagLocalPort
			},
			errorText: "local port is absent but contains",
		},
		{
			name: "attempt timestamps differ",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.KernelTimestampNS++
			},
			errorText: "does not match event timestamp",
		},
		{
			name: "attempt established timestamp",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.EstablishedTimestampNS =
					event.KernelTimestampNS
			},
			errorText: "contains an established timestamp",
		},
		{
			name: "non-failure failure source",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.FailureSource =
					kernelTCPLifecycleFailureSourceTCPState
			},
			errorText: "non-failure TCP lifecycle event",
		},
		{
			name: "failure missing source",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.EventType =
					kernelTCPLifecycleEventTypeConnectFailed
				event.KernelTimestampNS++
			},
			errorText: "unsupported failure source",
		},
		{
			name: "failure invalid errno",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.EventType =
					kernelTCPLifecycleEventTypeConnectFailed
				event.KernelTimestampNS++
				event.FailureSource =
					kernelTCPLifecycleFailureSourceConnectReturn
				event.Flags |=
					kernelTCPLifecycleFlagErrorCode
				event.ErrorCode = -unix.ECONNREFUSED
			},
			errorText: "invalid error code",
		},
		{
			name: "closed without establishment",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.EventType =
					kernelTCPLifecycleEventTypeClosed
				event.KernelTimestampNS++
			},
			errorText: "has no established timestamp",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			event := validIPv4TCPLifecycleAttempt()
			test.mutate(&event)

			err := validateKernelTCPLifecycleEvent(event)
			if err == nil {
				t.Fatal("validation succeeded; want an error")
			}

			if !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf(
					"error = %q; want text %q",
					err,
					test.errorText,
				)
			}
		})
	}
}

func validIPv4TCPLifecycleAttempt() kernelTCPLifecycleEvent {
	event := kernelTCPLifecycleEvent{
		ABIVersion:    kernelTCPLifecycleEventABIVersion,
		EventType:     kernelTCPLifecycleEventTypeConnectAttempt,
		Protocol:      kernelNetworkProtocolTCP,
		AddressFamily: unix.AF_INET,
		Flags: kernelTCPLifecycleFlagLocalAddress |
			kernelTCPLifecycleFlagLocalPort |
			kernelTCPLifecycleFlagRemoteAddress |
			kernelTCPLifecycleFlagRemotePort,
		PID:                 1234,
		UID:                 1000,
		ConnectionID:        42,
		KernelTimestampNS:   1_000,
		AttemptTimestampNS:  1_000,
		LocalAddressLength:  kernelAddressLengthIPv4,
		RemoteAddressLength: kernelAddressLengthIPv4,
		LocalPort:           40_000,
		RemotePort:          443,
	}

	copy(
		event.LocalAddress[:],
		net.IPv4(192, 0, 2, 10).To4(),
	)

	copy(
		event.RemoteAddress[:],
		net.IPv4(198, 51, 100, 20).To4(),
	)

	copy(event.Task[:], []byte("curl"))

	return event
}

func validIPv6TCPLifecycleAttempt() kernelTCPLifecycleEvent {
	event := kernelTCPLifecycleEvent{
		ABIVersion:    kernelTCPLifecycleEventABIVersion,
		EventType:     kernelTCPLifecycleEventTypeConnectAttempt,
		Protocol:      kernelNetworkProtocolTCP,
		AddressFamily: unix.AF_INET6,
		Flags: kernelTCPLifecycleFlagLocalAddress |
			kernelTCPLifecycleFlagLocalPort |
			kernelTCPLifecycleFlagRemoteAddress |
			kernelTCPLifecycleFlagRemotePort,
		PID:                 5678,
		UID:                 1000,
		ConnectionID:        84,
		KernelTimestampNS:   2_000,
		AttemptTimestampNS:  2_000,
		LocalAddressLength:  kernelAddressLengthIPv6,
		RemoteAddressLength: kernelAddressLengthIPv6,
		LocalPort:           40_001,
		RemotePort:          8443,
	}

	localIP := net.ParseIP("2001:db8::10").To16()
	if localIP == nil {
		panic("invalid static IPv6 local test address")
	}

	remoteIP := net.ParseIP("2001:db8::20").To16()
	if remoteIP == nil {
		panic("invalid static IPv6 remote test address")
	}

	copy(event.LocalAddress[:], localIP)
	copy(event.RemoteAddress[:], remoteIP)
	copy(event.Task[:], []byte("curl"))

	return event
}

func lifecycleEventTypeTestName(eventType uint8) string {
	switch eventType {
	case kernelTCPLifecycleEventTypeConnectAttempt:
		return "connect_attempt"
	case kernelTCPLifecycleEventTypeEstablished:
		return "established"
	case kernelTCPLifecycleEventTypeConnectFailed:
		return "connect_failed"
	case kernelTCPLifecycleEventTypeClosed:
		return "closed"
	default:
		return "unknown"
	}
}
