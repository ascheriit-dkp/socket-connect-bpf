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
		{"ABIVersion", unsafe.Offsetof(event.ABIVersion), 0},
		{"EventType", unsafe.Offsetof(event.EventType), 2},
		{"Protocol", unsafe.Offsetof(event.Protocol), 3},
		{"AddressFamily", unsafe.Offsetof(event.AddressFamily), 4},
		{"Flags", unsafe.Offsetof(event.Flags), 6},
		{"PID", unsafe.Offsetof(event.PID), 8},
		{"UID", unsafe.Offsetof(event.UID), 12},
		{"ConnectionID", unsafe.Offsetof(event.ConnectionID), 16},
		{
			"KernelTimestampNS",
			unsafe.Offsetof(event.KernelTimestampNS),
			24,
		},
		{
			"AttemptTimestampNS",
			unsafe.Offsetof(event.AttemptTimestampNS),
			32,
		},
		{
			"EstablishedTimestampNS",
			unsafe.Offsetof(event.EstablishedTimestampNS),
			40,
		},
		{"ErrorCode", unsafe.Offsetof(event.ErrorCode), 48},
		{"FailureSource", unsafe.Offsetof(event.FailureSource), 52},
		{
			"LocalAddressLength",
			unsafe.Offsetof(event.LocalAddressLength),
			53,
		},
		{
			"RemoteAddressLength",
			unsafe.Offsetof(event.RemoteAddressLength),
			54,
		},
		{"Reserved0", unsafe.Offsetof(event.Reserved0), 55},
		{"LocalPort", unsafe.Offsetof(event.LocalPort), 56},
		{"RemotePort", unsafe.Offsetof(event.RemotePort), 58},
		{"LocalAddress", unsafe.Offsetof(event.LocalAddress), 60},
		{"RemoteAddress", unsafe.Offsetof(event.RemoteAddress), 76},
		{"Task", unsafe.Offsetof(event.Task), 92},
		{"Reserved", unsafe.Offsetof(event.Reserved), 108},
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

	tests := []struct {
		name       string
		event      kernelTCPLifecycleEvent
		wantLocal  string
		wantRemote string
	}{
		{
			name:       "IPv4",
			event:      validIPv4TCPLifecycleAttempt(),
			wantLocal:  "192.0.2.10",
			wantRemote: "198.51.100.20",
		},
		{
			name:       "IPv6",
			event:      validIPv6TCPLifecycleAttempt(),
			wantLocal:  "2001:db8::10",
			wantRemote: "2001:db8::20",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.event.localIP(); !got.Equal(
				net.ParseIP(test.wantLocal),
			) {
				t.Fatalf(
					"local IP = %v; want %s",
					got,
					test.wantLocal,
				)
			}

			if got := test.event.remoteIP(); !got.Equal(
				net.ParseIP(test.wantRemote),
			) {
				t.Fatalf(
					"remote IP = %v; want %s",
					got,
					test.wantRemote,
				)
			}
		})
	}

	event := validIPv4TCPLifecycleAttempt()
	event.Flags &^= kernelTCPLifecycleFlagLocalAddress
	event.LocalAddressLength = kernelAddressLengthNone
	event.LocalAddress = [net.IPv6len]byte{}

	if got := event.localIP(); got != nil {
		t.Fatalf("absent local IP = %v; want nil", got)
	}
}

func TestKernelTCPLifecycleEventTiming(t *testing.T) {
	t.Parallel()

	t.Run("established connect latency", func(t *testing.T) {
		t.Parallel()

		event := validIPv4TCPLifecycleAttempt()
		event.EventType = kernelTCPLifecycleEventTypeEstablished
		event.KernelTimestampNS = 1_750
		event.EstablishedTimestampNS = 1_750

		got, ok := event.connectLatencyNS()
		if !ok || got != 750 {
			t.Fatalf(
				"connect latency = %d, %t; want 750, true",
				got,
				ok,
			)
		}
	})

	t.Run("failed connect latency", func(t *testing.T) {
		t.Parallel()

		event := validIPv4TCPLifecycleAttempt()
		event.EventType = kernelTCPLifecycleEventTypeConnectFailed
		event.KernelTimestampNS = 1_750
		event.FailureSource =
			kernelTCPLifecycleFailureSourceTCPState

		got, ok := event.connectLatencyNS()
		if !ok || got != 750 {
			t.Fatalf(
				"connect latency = %d, %t; want 750, true",
				got,
				ok,
			)
		}
	})

	t.Run("closed duration", func(t *testing.T) {
		t.Parallel()

		event := validIPv4TCPLifecycleAttempt()
		event.EventType = kernelTCPLifecycleEventTypeClosed
		event.KernelTimestampNS = 5_000
		event.EstablishedTimestampNS = 2_000

		got, ok := event.connectionDurationNS()
		if !ok || got != 3_000 {
			t.Fatalf(
				"connection duration = %d, %t; want 3000, true",
				got,
				ok,
			)
		}
	})

	event := validIPv4TCPLifecycleAttempt()

	if got, ok := event.connectLatencyNS(); ok {
		t.Fatalf(
			"attempt connect latency = %d, true; want unavailable",
			got,
		)
	}

	if got, ok := event.connectionDurationNS(); ok {
		t.Fatalf(
			"attempt duration = %d, true; want unavailable",
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
				event.ErrorCode =
					int32(unix.ECONNREFUSED)
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
		name      string
		mutate    func(*kernelTCPLifecycleEvent)
		errorText string
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
				event.RemoteAddress =
					[net.IPv6len]byte{}
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
				event.ErrorCode =
					-int32(unix.ECONNREFUSED)
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
