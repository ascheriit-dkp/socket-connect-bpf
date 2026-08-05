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
	"time"

	"github.com/ascheriit-dkp/socket-connect-bpf/conv"
	"golang.org/x/sys/unix"
)

const (
	tcpLifecycleEventTypeConnectAttempt = "connect_attempt"
	tcpLifecycleEventTypeEstablished    = "tcp_established"
	tcpLifecycleEventTypeConnectFailed  = "tcp_connect_failed"
	tcpLifecycleEventTypeClosed         = "tcp_closed"

	tcpLifecycleProtocolTCP = "tcp"

	tcpLifecycleFailureSourceConnectReturn = "connect_return"
	tcpLifecycleFailureSourceTCPState      = "tcp_state"
	tcpLifecycleFailureSourceSocketError   = "socket_error"
)

// tcpLifecycleEventPayload is the validated userspace representation used by
// lifecycle output encoders. It deliberately remains separate from
// eventPayload so attempt-only table output and NDJSON schema version 1 remain
// unchanged.
type tcpLifecycleEventPayload struct {
	ObservedAt time.Time

	EventType              string
	Protocol               string
	AddressFamily          string
	ConnectionID           uint64
	KernelTimestampNS      uint64
	AttemptTimestampNS     uint64
	EstablishedTimestampNS *uint64

	PID  uint32
	UID  uint32
	Comm string

	Local  tcpLifecycleEndpointPayload
	Remote tcpLifecycleEndpointPayload

	FailureSource string
	Errno         *int32
	Error         string

	ConnectLatencyNS     *uint64
	ConnectionDurationNS *uint64
}

// tcpLifecycleEndpointPayload preserves whether an endpoint component was
// observed. An absent address or port is not represented as a fabricated zero
// value.
type tcpLifecycleEndpointPayload struct {
	IP   net.IP
	Port *uint16
}

func newTCPLifecycleEventPayload(
	event kernelTCPLifecycleEvent,
	observedAt time.Time,
) (tcpLifecycleEventPayload, error) {
	if err := validateKernelTCPLifecycleEvent(event); err != nil {
		return tcpLifecycleEventPayload{}, fmt.Errorf(
			"build TCP lifecycle payload: %w",
			err,
		)
	}

	payload := tcpLifecycleEventPayload{
		ObservedAt:         observedAt,
		Protocol:           tcpLifecycleProtocolTCP,
		AddressFamily:      conv.ToAddressFamily(int(event.AddressFamily)),
		ConnectionID:       event.ConnectionID,
		KernelTimestampNS:  event.KernelTimestampNS,
		AttemptTimestampNS: event.AttemptTimestampNS,
		PID:                event.PID,
		UID:                event.UID,
		Comm:               unix.ByteSliceToString(event.Task[:]),
		Local: newTCPLifecycleEndpointPayload(
			event.Flags&kernelTCPLifecycleFlagLocalAddress != 0,
			event.localIP(),
			event.Flags&kernelTCPLifecycleFlagLocalPort != 0,
			event.LocalPort,
		),
		Remote: newTCPLifecycleEndpointPayload(
			event.Flags&kernelTCPLifecycleFlagRemoteAddress != 0,
			event.remoteIP(),
			event.Flags&kernelTCPLifecycleFlagRemotePort != 0,
			event.RemotePort,
		),
	}

	if event.EstablishedTimestampNS != 0 {
		payload.EstablishedTimestampNS = uint64Pointer(
			event.EstablishedTimestampNS,
		)
	}

	switch event.EventType {
	case kernelTCPLifecycleEventTypeConnectAttempt:
		payload.EventType = tcpLifecycleEventTypeConnectAttempt

	case kernelTCPLifecycleEventTypeEstablished:
		payload.EventType = tcpLifecycleEventTypeEstablished
		payload.ConnectLatencyNS = lifecycleDurationPointer(
			event.connectLatencyNS,
		)

	case kernelTCPLifecycleEventTypeConnectFailed:
		payload.EventType = tcpLifecycleEventTypeConnectFailed
		payload.ConnectLatencyNS = lifecycleDurationPointer(
			event.connectLatencyNS,
		)

		failureSource, err := tcpLifecycleFailureSource(event.FailureSource)
		if err != nil {
			return tcpLifecycleEventPayload{}, err
		}
		payload.FailureSource = failureSource

		if event.Flags&kernelTCPLifecycleFlagErrorCode != 0 {
			payload.Errno = int32Pointer(event.ErrorCode)
			payload.Error = unix.Errno(event.ErrorCode).Error()
		}

	case kernelTCPLifecycleEventTypeClosed:
		payload.EventType = tcpLifecycleEventTypeClosed
		payload.ConnectionDurationNS = lifecycleDurationPointer(
			event.connectionDurationNS,
		)

	default:
		return tcpLifecycleEventPayload{}, fmt.Errorf(
			"build TCP lifecycle payload: unsupported event type %d",
			event.EventType,
		)
	}

	return payload, nil
}

func newTCPLifecycleEndpointPayload(
	hasAddress bool,
	ip net.IP,
	hasPort bool,
	port uint16,
) tcpLifecycleEndpointPayload {
	endpoint := tcpLifecycleEndpointPayload{}

	if hasAddress {
		endpoint.IP = append(net.IP(nil), ip...)
	}

	if hasPort {
		endpoint.Port = uint16Pointer(port)
	}

	return endpoint
}

func tcpLifecycleFailureSource(source uint8) (string, error) {
	switch source {
	case kernelTCPLifecycleFailureSourceConnectReturn:
		return tcpLifecycleFailureSourceConnectReturn, nil
	case kernelTCPLifecycleFailureSourceTCPState:
		return tcpLifecycleFailureSourceTCPState, nil
	case kernelTCPLifecycleFailureSourceSocketError:
		return tcpLifecycleFailureSourceSocketError, nil
	default:
		return "", fmt.Errorf(
			"build TCP lifecycle payload: unsupported failure source %d",
			source,
		)
	}
}

func lifecycleDurationPointer(
	duration func() (uint64, bool),
) *uint64 {
	value, ok := duration()
	if !ok {
		return nil
	}

	return uint64Pointer(value)
}

func uint16Pointer(value uint16) *uint16 {
	return &value
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func int32Pointer(value int32) *int32 {
	return &value
}
