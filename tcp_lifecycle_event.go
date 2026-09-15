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
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const (
	kernelTCPLifecycleEventABIVersion uint16 = 2

	kernelTCPLifecycleEventTypeConnectAttempt uint8 = 1
	kernelTCPLifecycleEventTypeEstablished    uint8 = 2
	kernelTCPLifecycleEventTypeConnectFailed  uint8 = 3
	kernelTCPLifecycleEventTypeClosed         uint8 = 4

	kernelNetworkProtocolTCP uint8 = unix.IPPROTO_TCP

	kernelTCPLifecycleFlagLocalAddress  uint16 = 1 << 0
	kernelTCPLifecycleFlagLocalPort     uint16 = 1 << 1
	kernelTCPLifecycleFlagRemoteAddress uint16 = 1 << 2
	kernelTCPLifecycleFlagRemotePort    uint16 = 1 << 3
	kernelTCPLifecycleFlagErrorCode     uint16 = 1 << 4

	kernelTCPLifecycleKnownFlags uint16 = kernelTCPLifecycleFlagLocalAddress |
		kernelTCPLifecycleFlagLocalPort |
		kernelTCPLifecycleFlagRemoteAddress |
		kernelTCPLifecycleFlagRemotePort |
		kernelTCPLifecycleFlagErrorCode

	kernelTCPLifecycleFailureSourceNone          uint8 = 0
	kernelTCPLifecycleFailureSourceConnectReturn uint8 = 1
	kernelTCPLifecycleFailureSourceTCPState      uint8 = 2
	kernelTCPLifecycleFailureSourceSocketError   uint8 = 3

	kernelTCPLifecycleEventBinarySize = 112
)

// kernelTCPLifecycleEvent is the userspace representation of the internal
// fixed-size TCP lifecycle record.
//
// This ABI is separate from kernelSocketEvent ABI version 1 so that the
// existing attempt-only pipeline remains unchanged while lifecycle support is
// developed.
//
// Field order and sizes are part of the internal kernel-to-userspace ABI.
// Changes require a new ABI version and a corresponding decoder.
type kernelTCPLifecycleEvent struct {
	ABIVersion    uint16
	EventType     uint8
	Protocol      uint8
	AddressFamily uint16
	Flags         uint16

	PID uint32
	UID uint32

	ConnectionID           uint64
	KernelTimestampNS      uint64
	AttemptTimestampNS     uint64
	EstablishedTimestampNS uint64

	ErrorCode     int32
	FailureSource uint8

	LocalAddressLength  uint8
	RemoteAddressLength uint8
	Reserved0           uint8

	LocalPort  uint16
	RemotePort uint16

	LocalAddress  [net.IPv6len]byte
	RemoteAddress [net.IPv6len]byte
	Task          [16]byte
	Reserved      [4]byte
}

// localIP returns an independent net.IP value when the local address is
// present and has a supported length.
func (event kernelTCPLifecycleEvent) localIP() net.IP {
	if event.Flags&kernelTCPLifecycleFlagLocalAddress == 0 {
		return nil
	}

	return lifecycleEndpointIP(
		event.LocalAddressLength,
		event.LocalAddress,
	)
}

// remoteIP returns an independent net.IP value when the remote address is
// present and has a supported length.
func (event kernelTCPLifecycleEvent) remoteIP() net.IP {
	if event.Flags&kernelTCPLifecycleFlagRemoteAddress == 0 {
		return nil
	}

	return lifecycleEndpointIP(
		event.RemoteAddressLength,
		event.RemoteAddress,
	)
}

// connectLatencyNS returns the monotonic duration between the tracked attempt
// and its observed establishment or failure.
func (event kernelTCPLifecycleEvent) connectLatencyNS() (uint64, bool) {
	switch event.EventType {
	case kernelTCPLifecycleEventTypeEstablished,
		kernelTCPLifecycleEventTypeConnectFailed:
	default:
		return 0, false
	}

	if event.AttemptTimestampNS == 0 ||
		event.KernelTimestampNS < event.AttemptTimestampNS {
		return 0, false
	}

	return event.KernelTimestampNS - event.AttemptTimestampNS, true
}

// connectionDurationNS returns the monotonic duration between establishment
// and observed closure.
func (event kernelTCPLifecycleEvent) connectionDurationNS() (uint64, bool) {
	if event.EventType != kernelTCPLifecycleEventTypeClosed {
		return 0, false
	}

	if event.EstablishedTimestampNS == 0 ||
		event.KernelTimestampNS < event.EstablishedTimestampNS {
		return 0, false
	}

	return event.KernelTimestampNS - event.EstablishedTimestampNS, true
}

func lifecycleEndpointIP(
	addressLength uint8,
	address [net.IPv6len]byte,
) net.IP {
	switch addressLength {
	case kernelAddressLengthIPv4:
		ip := make(net.IP, net.IPv4len)
		copy(ip, address[:net.IPv4len])

		return ip

	case kernelAddressLengthIPv6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, address[:net.IPv6len])

		return ip

	default:
		return nil
	}
}

func validateKernelTCPLifecycleEvent(
	event kernelTCPLifecycleEvent,
) error {
	if event.ABIVersion != kernelTCPLifecycleEventABIVersion {
		return fmt.Errorf(
			"unsupported TCP lifecycle event ABI version %d",
			event.ABIVersion,
		)
	}

	switch event.EventType {
	case kernelTCPLifecycleEventTypeConnectAttempt,
		kernelTCPLifecycleEventTypeEstablished,
		kernelTCPLifecycleEventTypeConnectFailed,
		kernelTCPLifecycleEventTypeClosed:
	default:
		return fmt.Errorf(
			"unsupported TCP lifecycle event type %d",
			event.EventType,
		)
	}

	if event.Protocol != kernelNetworkProtocolTCP {
		return fmt.Errorf(
			"unsupported TCP lifecycle protocol %d",
			event.Protocol,
		)
	}

	switch event.AddressFamily {
	case unix.AF_INET, unix.AF_INET6:
	default:
		return fmt.Errorf(
			"unsupported TCP lifecycle address family %d",
			event.AddressFamily,
		)
	}

	unknownFlags := event.Flags &^ kernelTCPLifecycleKnownFlags
	if unknownFlags != 0 {
		return fmt.Errorf(
			"unsupported TCP lifecycle flags 0x%x",
			unknownFlags,
		)
	}

	if event.PID == 0 {
		return fmt.Errorf("TCP lifecycle event has PID zero")
	}

	if event.ConnectionID == 0 {
		return fmt.Errorf("TCP lifecycle event has connection ID zero")
	}

	if event.KernelTimestampNS == 0 {
		return fmt.Errorf(
			"TCP lifecycle event has kernel timestamp zero",
		)
	}

	if event.AttemptTimestampNS == 0 {
		return fmt.Errorf(
			"TCP lifecycle event has attempt timestamp zero",
		)
	}

	if event.AttemptTimestampNS > event.KernelTimestampNS {
		return fmt.Errorf(
			"TCP lifecycle attempt timestamp %d is after event timestamp %d",
			event.AttemptTimestampNS,
			event.KernelTimestampNS,
		)
	}

	if event.Reserved0 != 0 {
		return fmt.Errorf(
			"TCP lifecycle reserved byte is non-zero",
		)
	}

	if event.Reserved != [4]byte{} {
		return fmt.Errorf(
			"TCP lifecycle reserved bytes are non-zero",
		)
	}

	if err := validateTCPLifecycleEndpoint(
		"local",
		event.AddressFamily,
		event.Flags&kernelTCPLifecycleFlagLocalAddress != 0,
		event.LocalAddressLength,
		event.LocalAddress,
	); err != nil {
		return err
	}

	if err := validateTCPLifecycleEndpoint(
		"remote",
		event.AddressFamily,
		event.Flags&kernelTCPLifecycleFlagRemoteAddress != 0,
		event.RemoteAddressLength,
		event.RemoteAddress,
	); err != nil {
		return err
	}

	if err := validateTCPLifecyclePort(
		"local",
		event.Flags&kernelTCPLifecycleFlagLocalPort != 0,
		event.LocalPort,
	); err != nil {
		return err
	}

	if err := validateTCPLifecyclePort(
		"remote",
		event.Flags&kernelTCPLifecycleFlagRemotePort != 0,
		event.RemotePort,
	); err != nil {
		return err
	}

	if event.Flags&kernelTCPLifecycleFlagRemoteAddress == 0 {
		return fmt.Errorf(
			"TCP lifecycle event has no remote address",
		)
	}

	if event.Flags&kernelTCPLifecycleFlagRemotePort == 0 {
		return fmt.Errorf(
			"TCP lifecycle event has no remote port",
		)
	}

	switch event.EventType {
	case kernelTCPLifecycleEventTypeConnectAttempt:
		if event.AttemptTimestampNS != event.KernelTimestampNS {
			return fmt.Errorf(
				"TCP attempt timestamp %d does not match event timestamp %d",
				event.AttemptTimestampNS,
				event.KernelTimestampNS,
			)
		}

		if event.EstablishedTimestampNS != 0 {
			return fmt.Errorf(
				"TCP attempt contains an established timestamp",
			)
		}

		return validateTCPLifecycleNonFailure(event)

	case kernelTCPLifecycleEventTypeEstablished:
		if event.EstablishedTimestampNS != event.KernelTimestampNS {
			return fmt.Errorf(
				"TCP established timestamp %d does not match event timestamp %d",
				event.EstablishedTimestampNS,
				event.KernelTimestampNS,
			)
		}

		return validateTCPLifecycleNonFailure(event)

	case kernelTCPLifecycleEventTypeConnectFailed:
		if event.EstablishedTimestampNS != 0 {
			return fmt.Errorf(
				"failed TCP connection contains an established timestamp",
			)
		}

		return validateTCPLifecycleFailure(event)

	case kernelTCPLifecycleEventTypeClosed:
		if event.EstablishedTimestampNS == 0 {
			return fmt.Errorf(
				"closed TCP connection has no established timestamp",
			)
		}

		if event.EstablishedTimestampNS < event.AttemptTimestampNS {
			return fmt.Errorf(
				"TCP established timestamp %d is before attempt timestamp %d",
				event.EstablishedTimestampNS,
				event.AttemptTimestampNS,
			)
		}

		if event.EstablishedTimestampNS >
			event.KernelTimestampNS {
			return fmt.Errorf(
				"TCP established timestamp %d is after closure timestamp %d",
				event.EstablishedTimestampNS,
				event.KernelTimestampNS,
			)
		}

		return validateTCPLifecycleNonFailure(event)
	}

	return nil
}

func validateTCPLifecycleEndpoint(
	name string,
	addressFamily uint16,
	present bool,
	addressLength uint8,
	address [net.IPv6len]byte,
) error {
	if !present {
		if addressLength != kernelAddressLengthNone {
			return fmt.Errorf(
				"TCP lifecycle %s address is absent but has length %d",
				name,
				addressLength,
			)
		}

		if address != [net.IPv6len]byte{} {
			return fmt.Errorf(
				"TCP lifecycle %s address is absent but contains data",
				name,
			)
		}

		return nil
	}

	var expectedLength uint8

	switch addressFamily {
	case unix.AF_INET:
		expectedLength = kernelAddressLengthIPv4
	case unix.AF_INET6:
		expectedLength = kernelAddressLengthIPv6
	default:
		return fmt.Errorf(
			"unsupported TCP lifecycle address family %d",
			addressFamily,
		)
	}

	if addressLength != expectedLength {
		return fmt.Errorf(
			"TCP lifecycle %s address length is %d; want %d",
			name,
			addressLength,
			expectedLength,
		)
	}

	if expectedLength == kernelAddressLengthIPv4 {
		for _, value := range address[net.IPv4len:] {
			if value != 0 {
				return fmt.Errorf(
					"TCP lifecycle IPv4 %s address has non-zero padding",
					name,
				)
			}
		}
	}

	return nil
}

func validateTCPLifecyclePort(
	name string,
	present bool,
	port uint16,
) error {
	if !present {
		if port != 0 {
			return fmt.Errorf(
				"TCP lifecycle %s port is absent but contains %d",
				name,
				port,
			)
		}

		return nil
	}

	return nil
}

func validateTCPLifecycleNonFailure(
	event kernelTCPLifecycleEvent,
) error {
	if event.FailureSource !=
		kernelTCPLifecycleFailureSourceNone {
		return fmt.Errorf(
			"non-failure TCP lifecycle event has failure source %d",
			event.FailureSource,
		)
	}

	if event.Flags&kernelTCPLifecycleFlagErrorCode != 0 {
		return fmt.Errorf(
			"non-failure TCP lifecycle event has an error-code flag",
		)
	}

	if event.ErrorCode != 0 {
		return fmt.Errorf(
			"non-failure TCP lifecycle event has error code %d",
			event.ErrorCode,
		)
	}

	return nil
}

func validateTCPLifecycleFailure(
	event kernelTCPLifecycleEvent,
) error {
	switch event.FailureSource {
	case kernelTCPLifecycleFailureSourceConnectReturn,
		kernelTCPLifecycleFailureSourceTCPState,
		kernelTCPLifecycleFailureSourceSocketError:
	default:
		return fmt.Errorf(
			"failed TCP connection has unsupported failure source %d",
			event.FailureSource,
		)
	}

	hasErrorCode :=
		event.Flags&kernelTCPLifecycleFlagErrorCode != 0

	if !hasErrorCode {
		if event.ErrorCode != 0 {
			return fmt.Errorf(
				"failed TCP connection has an unflagged error code %d",
				event.ErrorCode,
			)
		}

		return nil
	}

	if event.ErrorCode <= 0 {
		return fmt.Errorf(
			"failed TCP connection has invalid error code %d",
			event.ErrorCode,
		)
	}

	return nil
}
