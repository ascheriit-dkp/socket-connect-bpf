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
	"testing"
	"unsafe"
)

func TestKernelSocketEventLayout(t *testing.T) {
	t.Parallel()

	var event kernelSocketEvent

	if got := binary.Size(event); got != kernelSocketEventBinarySize {
		t.Fatalf(
			"binary size = %d; want %d",
			got,
			kernelSocketEventBinarySize,
		)
	}

	if got := int(unsafe.Sizeof(event)); got != kernelSocketEventBinarySize {
		t.Fatalf(
			"memory size = %d; want %d",
			got,
			kernelSocketEventBinarySize,
		)
	}

	expectedOffsets := []struct {
		name string
		got  uintptr
		want uintptr
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
			name: "AddressLength",
			got:  unsafe.Offsetof(event.AddressLength),
			want: 3,
		},
		{
			name: "AddressFamily",
			got:  unsafe.Offsetof(event.AddressFamily),
			want: 4,
		},
		{
			name: "DestinationPort",
			got:  unsafe.Offsetof(event.DestinationPort),
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
			name: "KernelTimestampNS",
			got:  unsafe.Offsetof(event.KernelTimestampNS),
			want: 16,
		},
		{
			name: "DestinationAddress",
			got:  unsafe.Offsetof(event.DestinationAddress),
			want: 24,
		},
		{
			name: "Task",
			got:  unsafe.Offsetof(event.Task),
			want: 40,
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

func TestKernelSocketEventDestinationIPv4(t *testing.T) {
	t.Parallel()

	event := kernelSocketEvent{
		AddressLength: kernelAddressLengthIPv4,
		DestinationAddress: [net.IPv6len]byte{
			203,
			0,
			113,
			10,
		},
	}

	got := event.destinationIP()
	want := net.ParseIP("203.0.113.10")

	if !got.Equal(want) {
		t.Fatalf(
			"destination IP = %v; want %v",
			got,
			want,
		)
	}
}

func TestKernelSocketEventDestinationIPv6(t *testing.T) {
	t.Parallel()

	want := net.ParseIP("2001:db8::1").To16()
	if want == nil {
		t.Fatal("parsing IPv6 test address returned nil")
	}

	event := kernelSocketEvent{
		AddressLength: kernelAddressLengthIPv6,
	}

	copy(event.DestinationAddress[:], want)

	got := event.destinationIP()

	if !got.Equal(want) {
		t.Fatalf(
			"destination IP = %v; want %v",
			got,
			want,
		)
	}
}

func TestKernelSocketEventDestinationIPRejectsUnsupportedLength(
	t *testing.T,
) {
	t.Parallel()

	for _, addressLength := range []uint8{
		kernelAddressLengthNone,
		5,
		15,
		17,
	} {
		addressLength := addressLength

		t.Run(
			string(rune(addressLength)),
			func(t *testing.T) {
				t.Parallel()

				event := kernelSocketEvent{
					AddressLength: addressLength,
				}

				if got := event.destinationIP(); got != nil {
					t.Fatalf(
						"destination IP = %v; want nil",
						got,
					)
				}
			},
		)
	}
}
