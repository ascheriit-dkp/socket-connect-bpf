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
)

func TestDecodeTCPLifecycleEventPayload(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(
		2026,
		time.August,
		6,
		9,
		45,
		0,
		123,
		time.UTC,
	)

	event := validIPv4TCPLifecycleAttempt()
	event.EventType = kernelTCPLifecycleEventTypeEstablished
	event.KernelTimestampNS = 1_500
	event.EstablishedTimestampNS = 1_500

	got, err := decodeTCPLifecycleEventPayload(
		encodeKernelTCPLifecycleEvent(t, event),
		observedAt,
	)
	if err != nil {
		t.Fatalf("decoding lifecycle payload: %v", err)
	}

	assertTCPLifecyclePayloadCommonFields(
		t,
		got,
		event,
		observedAt,
	)

	if got.EventType != tcpLifecycleEventTypeEstablished {
		t.Fatalf(
			"event type = %q; want %q",
			got.EventType,
			tcpLifecycleEventTypeEstablished,
		)
	}

	assertOptionalUint64(
		t,
		"established timestamp",
		got.EstablishedTimestampNS,
		uint64Pointer(1_500),
	)
	assertOptionalUint64(
		t,
		"connect latency",
		got.ConnectLatencyNS,
		uint64Pointer(500),
	)
}

func TestDecodeTCPLifecycleEventPayloadRejectsRecordSizes(t *testing.T) {
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

			got, err := decodeTCPLifecycleEventPayload(
				test.rawSample,
				time.Now(),
			)
			if err == nil {
				t.Fatal("decoding succeeded; want an error")
			}

			if !strings.Contains(
				err.Error(),
				"decode TCP lifecycle record",
			) {
				t.Fatalf(
					"error = %q; want record context",
					err,
				)
			}

			if !strings.Contains(
				err.Error(),
				"unexpected TCP lifecycle record size",
			) {
				t.Fatalf(
					"error = %q; want size detail",
					err,
				)
			}

			assertZeroTCPLifecyclePayload(t, got)
		})
	}
}

func TestDecodeTCPLifecycleEventPayloadRejectsInvalidRecord(t *testing.T) {
	t.Parallel()

	event := validIPv4TCPLifecycleAttempt()
	event.ConnectionID = 0

	got, err := decodeTCPLifecycleEventPayload(
		encodeKernelTCPLifecycleEvent(t, event),
		time.Now(),
	)
	if err == nil {
		t.Fatal("decoding succeeded; want an error")
	}

	if !strings.Contains(err.Error(), "decode TCP lifecycle record") {
		t.Fatalf("error = %q; want record context", err)
	}

	if !strings.Contains(err.Error(), "connection ID zero") {
		t.Fatalf("error = %q; want validation detail", err)
	}

	assertZeroTCPLifecyclePayload(t, got)
}

func assertZeroTCPLifecyclePayload(
	t *testing.T,
	payload tcpLifecycleEventPayload,
) {
	t.Helper()

	if payload.EventType != "" ||
		payload.ConnectionID != 0 ||
		payload.KernelTimestampNS != 0 ||
		payload.Local.IP != nil ||
		payload.Local.Port != nil ||
		payload.Remote.IP != nil ||
		payload.Remote.Port != nil {
		t.Fatalf("payload = %#v; want zero value", payload)
	}
}
