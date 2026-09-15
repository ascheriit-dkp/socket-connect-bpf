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
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDecodeUDPEventIPv4(t *testing.T) {
	event := validKernelUDPEventIPv4()
	payload, err := decodeUDPEventPayload(encodeKernelUDPEvent(t, event), time.Unix(1, 2))
	if err != nil {
		t.Fatal(err)
	}

	if payload.EventType != udpEventTypeSend || payload.Protocol != udpProtocol {
		t.Fatalf("unexpected UDP identity: %#v", payload)
	}
	if payload.PID != 1234 || payload.UID != 1000 || payload.CgroupID != 99 {
		t.Fatalf("unexpected process identity: %#v", payload)
	}
	if payload.Comm != "sender" {
		t.Fatalf("comm = %q", payload.Comm)
	}
	if !payload.Remote.IP.Equal(net.ParseIP("192.0.2.25")) {
		t.Fatalf("remote IP = %v", payload.Remote.IP)
	}
	if payload.Remote.Port == nil || *payload.Remote.Port != 5353 {
		t.Fatalf("remote port = %#v", payload.Remote.Port)
	}
}

func TestDecodeUDPEventIPv6(t *testing.T) {
	event := validKernelUDPEventIPv4()
	event.AddressFamily = unix.AF_INET6
	event.AddressLength = net.IPv6len
	event.RemoteAddress = [net.IPv6len]byte{}
	copy(event.RemoteAddress[:], net.ParseIP("2001:db8::25").To16())

	payload, err := decodeUDPEventPayload(encodeKernelUDPEvent(t, event), time.Unix(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	if !payload.Remote.IP.Equal(net.ParseIP("2001:db8::25")) {
		t.Fatalf("remote IP = %v", payload.Remote.IP)
	}
}

func TestValidateKernelUDPEventRejectsInvalidRecords(t *testing.T) {
	tests := map[string]func(*kernelUDPEvent){
		"ABI": func(event *kernelUDPEvent) { event.ABIVersion = 2 },
		"type": func(event *kernelUDPEvent) { event.EventType = 2 },
		"PID": func(event *kernelUDPEvent) { event.PID = 0 },
		"timestamp": func(event *kernelUDPEvent) { event.KernelTimestampNS = 0 },
		"port": func(event *kernelUDPEvent) { event.RemotePort = 0 },
		"family": func(event *kernelUDPEvent) { event.AddressFamily = unix.AF_UNIX },
		"length": func(event *kernelUDPEvent) { event.AddressLength = 16 },
		"IPv4 padding": func(event *kernelUDPEvent) { event.RemoteAddress[4] = 1 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			event := validKernelUDPEventIPv4()
			mutate(&event)
			if err := validateKernelUDPEvent(event); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func validKernelUDPEventIPv4() kernelUDPEvent {
	event := kernelUDPEvent{
		ABIVersion:       kernelUDPEventABIVersion,
		EventType:        kernelUDPEventTypeSend,
		AddressLength:    net.IPv4len,
		AddressFamily:    unix.AF_INET,
		RemotePort:       5353,
		PID:              1234,
		UID:              1000,
		KernelTimestampNS: 123456,
		CgroupID:         99,
	}
	copy(event.RemoteAddress[:], net.ParseIP("192.0.2.25").To4())
	copy(event.Task[:], []byte("sender"))
	return event
}

func encodeKernelUDPEvent(t *testing.T, event kernelUDPEvent) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, event); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != kernelUDPEventBinarySize {
		t.Fatalf("encoded size = %d; want %d", buffer.Len(), kernelUDPEventBinarySize)
	}
	return buffer.Bytes()
}
