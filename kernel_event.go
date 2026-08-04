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

import "net"

const (
	kernelEventABIVersion uint16 = 1

	kernelEventTypeConnectAttempt uint8 = 1

	kernelAddressLengthNone uint8 = 0
	kernelAddressLengthIPv4 uint8 = net.IPv4len
	kernelAddressLengthIPv6 uint8 = net.IPv6len

	kernelSocketEventBinarySize = 56
)

// kernelSocketEvent is the userspace representation of the fixed event record
// shared with the eBPF program.
//
// Field order and sizes are part of the internal kernel-to-userspace ABI.
// Changes require a new kernelEventABIVersion and corresponding decoder.
type kernelSocketEvent struct {
	ABIVersion         uint16
	EventType          uint8
	AddressLength      uint8
	AddressFamily      uint16
	DestinationPort    uint16
	PID                uint32
	UID                uint32
	KernelTimestampNS  uint64
	DestinationAddress [net.IPv6len]byte
	Task               [16]byte
}

// destinationIP returns an independent net.IP value for an IP event.
//
// A nil value indicates that the record contains no supported destination
// address.
func (event kernelSocketEvent) destinationIP() net.IP {
	switch event.AddressLength {
	case kernelAddressLengthIPv4:
		ip := make(net.IP, net.IPv4len)
		copy(ip, event.DestinationAddress[:net.IPv4len])

		return ip

	case kernelAddressLengthIPv6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, event.DestinationAddress[:net.IPv6len])

		return ip

	default:
		return nil
	}
}
