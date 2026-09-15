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
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecodeKernelTCPLifecycleEventRoundTrip(t *testing.T) {
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
				event.EventType = kernelTCPLifecycleEventTypeEstablished
				event.KernelTimestampNS = 1_500
				event.EstablishedTimestampNS = 1_500

				return event
			}(),
		},
		{
			name: "failed",
			event: func() kernelTCPLifecycleEvent {
				event := validIPv4TCPLifecycleAttempt()
				event.EventType = kernelTCPLifecycleEventTypeConnectFailed
				event.KernelTimestampNS = 1_250
				event.FailureSource = kernelTCPLifecycleFailureSourceTCPState

				return event
			}(),
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
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rawSample := encodeKernelTCPLifecycleEvent(t, test.event)

			got, err := decodeKernelTCPLifecycleEvent(rawSample)
			if err != nil {
				t.Fatalf("decoding event: %v", err)
			}

			if got != test.event {
				t.Fatalf(
					"decoded event = %#v; want %#v",
					got,
					test.event,
				)
			}
		})
	}
}

func TestDecodeKernelTCPLifecycleEventRejectsRecordSizes(t *testing.T) {
	t.Parallel()

	validRecord := encodeKernelTCPLifecycleEvent(
		t,
		validIPv4TCPLifecycleAttempt(),
	)

	tests := []struct {
		name      string
		rawSample []byte
	}{
		{
			name:      "empty",
			rawSample: nil,
		},
		{
			name:      "one byte short",
			rawSample: append([]byte(nil), validRecord[:len(validRecord)-1]...),
		},
		{
			name:      "one byte long",
			rawSample: append(append([]byte(nil), validRecord...), 0),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeKernelTCPLifecycleEvent(test.rawSample)
			if err == nil {
				t.Fatal("decoding succeeded; want an error")
			}

			if !strings.Contains(
				err.Error(),
				"unexpected TCP lifecycle record size",
			) {
				t.Fatalf(
					"error = %q; want record-size error",
					err,
				)
			}

			if got != (kernelTCPLifecycleEvent{}) {
				t.Fatalf("event = %#v; want zero value", got)
			}
		})
	}
}

func TestDecodeKernelTCPLifecycleEventRejectsInvalidRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*kernelTCPLifecycleEvent)
		errorText string
	}{
		{
			name: "unsupported ABI",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.ABIVersion = 99
			},
			errorText: "unsupported TCP lifecycle event ABI version",
		},
		{
			name: "unsupported event type",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.EventType = 99
			},
			errorText: "unsupported TCP lifecycle event type",
		},
		{
			name: "missing connection ID",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.ConnectionID = 0
			},
			errorText: "connection ID zero",
		},
		{
			name: "missing remote port",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Flags &^= kernelTCPLifecycleFlagRemotePort
				event.RemotePort = 0
			},
			errorText: "has no remote port",
		},
		{
			name: "non-zero reserved data",
			mutate: func(event *kernelTCPLifecycleEvent) {
				event.Reserved[0] = 1
			},
			errorText: "reserved bytes are non-zero",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			event := validIPv4TCPLifecycleAttempt()
			test.mutate(&event)

			got, err := decodeKernelTCPLifecycleEvent(
				encodeKernelTCPLifecycleEvent(t, event),
			)
			if err == nil {
				t.Fatal("decoding succeeded; want an error")
			}

			if !strings.Contains(
				err.Error(),
				"validate TCP lifecycle kernel event",
			) {
				t.Fatalf(
					"error = %q; want validation context",
					err,
				)
			}

			if !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf(
					"error = %q; want text %q",
					err,
					test.errorText,
				)
			}

			if got != (kernelTCPLifecycleEvent{}) {
				t.Fatalf("event = %#v; want zero value", got)
			}
		})
	}
}

func encodeKernelTCPLifecycleEvent(
	t *testing.T,
	event kernelTCPLifecycleEvent,
) []byte {
	t.Helper()

	var buffer bytes.Buffer

	if err := binary.Write(
		&buffer,
		binary.LittleEndian,
		event,
	); err != nil {
		t.Fatalf("encoding TCP lifecycle event: %v", err)
	}

	if got := buffer.Len(); got != kernelTCPLifecycleEventBinarySize {
		t.Fatalf(
			"encoded size = %d; want %d",
			got,
			kernelTCPLifecycleEventBinarySize,
		)
	}

	return buffer.Bytes()
}
