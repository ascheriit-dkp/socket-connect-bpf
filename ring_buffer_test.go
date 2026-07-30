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
// See the License for the specific language OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProcessSocketEventRecordRejectsUnexpectedSize(t *testing.T) {
	t.Parallel()

	for _, size := range []int{
		0,
		1,
		kernelSocketEventBinarySize - 1,
		kernelSocketEventBinarySize + 1,
	} {
		size := size

		t.Run(
			strings.ReplaceAll(
				"size "+string(rune(size)),
				" ",
				"_",
			),
			func(t *testing.T) {
				t.Parallel()

				err := processSocketEventRecord(make([]byte, size))
				if err == nil {
					t.Fatal("processing an invalid record size returned nil")
				}

				if !strings.Contains(
					err.Error(),
					"unexpected record size",
				) {
					t.Fatalf(
						"error = %q; want unexpected record size",
						err,
					)
				}
			},
		)
	}
}

func TestProcessSocketEventRecordRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		event     kernelSocketEvent
		wantError string
	}{
		{
			name: "unsupported ABI version",
			event: kernelSocketEvent{
				ABIVersion:      kernelEventABIVersion + 1,
				EventType:       kernelEventTypeConnectAttempt,
				AddressLength:   kernelAddressLengthIPv4,
				AddressFamily:   unix.AF_INET,
				DestinationPort: 443,
			},
			wantError: "unsupported kernel event ABI version",
		},
		{
			name: "unsupported event type",
			event: kernelSocketEvent{
				ABIVersion:      kernelEventABIVersion,
				EventType:       kernelEventTypeConnectAttempt + 1,
				AddressLength:   kernelAddressLengthIPv4,
				AddressFamily:   unix.AF_INET,
				DestinationPort: 443,
			},
			wantError: "unsupported kernel event type",
		},
		{
			name: "missing IPv4 address",
			event: kernelSocketEvent{
				ABIVersion:    kernelEventABIVersion,
				EventType:     kernelEventTypeConnectAttempt,
				AddressLength: kernelAddressLengthNone,
				AddressFamily: unix.AF_INET,
			},
			wantError: "has no destination address",
		},
		{
			name: "missing IPv6 address",
			event: kernelSocketEvent{
				ABIVersion:    kernelEventABIVersion,
				EventType:     kernelEventTypeConnectAttempt,
				AddressLength: kernelAddressLengthNone,
				AddressFamily: unix.AF_INET6,
			},
			wantError: "has no destination address",
		},
		{
			name: "IPv4 length with IPv6 family",
			event: kernelSocketEvent{
				ABIVersion:    kernelEventABIVersion,
				EventType:     kernelEventTypeConnectAttempt,
				AddressLength: kernelAddressLengthIPv4,
				AddressFamily: unix.AF_INET6,
			},
			wantError: "IPv4 address length used with address family",
		},
		{
			name: "IPv6 length with IPv4 family",
			event: kernelSocketEvent{
				ABIVersion:    kernelEventABIVersion,
				EventType:     kernelEventTypeConnectAttempt,
				AddressLength: kernelAddressLengthIPv6,
				AddressFamily: unix.AF_INET,
			},
			wantError: "IPv6 address length used with address family",
		},
		{
			name: "unsupported address length",
			event: kernelSocketEvent{
				ABIVersion:    kernelEventABIVersion,
				EventType:     kernelEventTypeConnectAttempt,
				AddressLength: 5,
				AddressFamily: unix.AF_INET,
			},
			wantError: "unsupported destination address length",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rawSample := encodeKernelSocketEventForTest(
				t,
				test.event,
			)

			err := processSocketEventRecord(rawSample)
			if err == nil {
				t.Fatal("processing invalid metadata returned nil")
			}

			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf(
					"error = %q; want substring %q",
					err,
					test.wantError,
				)
			}
		})
	}
}

func TestValidateKernelSocketEventAcceptsSupportedRecords(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name  string
		event kernelSocketEvent
	}{
		{
			name: "IPv4",
			event: kernelSocketEvent{
				ABIVersion:      kernelEventABIVersion,
				EventType:       kernelEventTypeConnectAttempt,
				AddressLength:   kernelAddressLengthIPv4,
				AddressFamily:   unix.AF_INET,
				DestinationPort: 443,
			},
		},
		{
			name: "IPv6",
			event: kernelSocketEvent{
				ABIVersion:      kernelEventABIVersion,
				EventType:       kernelEventTypeConnectAttempt,
				AddressLength:   kernelAddressLengthIPv6,
				AddressFamily:   unix.AF_INET6,
				DestinationPort: 443,
			},
		},
		{
			name: "non-IP address family",
			event: kernelSocketEvent{
				ABIVersion:    kernelEventABIVersion,
				EventType:     kernelEventTypeConnectAttempt,
				AddressLength: kernelAddressLengthNone,
				AddressFamily: unix.AF_NETLINK,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := validateKernelSocketEvent(test.event); err != nil {
				t.Fatalf(
					"validating supported event returned error: %v",
					err,
				)
			}
		})
	}
}

func encodeKernelSocketEventForTest(
	t *testing.T,
	event kernelSocketEvent,
) []byte {
	t.Helper()

	var buffer bytes.Buffer

	if err := binary.Write(
		&buffer,
		binary.LittleEndian,
		event,
	); err != nil {
		t.Fatalf("encoding kernel socket event: %v", err)
	}

	if buffer.Len() != kernelSocketEventBinarySize {
		t.Fatalf(
			"encoded size = %d; want %d",
			buffer.Len(),
			kernelSocketEventBinarySize,
		)
	}

	return buffer.Bytes()
}
