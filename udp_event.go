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
	"fmt"
	"net"
	"time"

	"github.com/ascheriit-dkp/socket-connect-bpf/conv"
	"golang.org/x/sys/unix"
)

const (
	kernelUDPEventABIVersion uint16 = 1
	kernelUDPEventTypeSend   uint8  = 1
	kernelUDPEventBinarySize        = 64

	udpEventTypeSend = "udp_send"
	udpProtocol      = "udp"
)

type kernelUDPEvent struct {
	ABIVersion    uint16
	EventType     uint8
	AddressLength uint8
	AddressFamily uint16
	RemotePort    uint16
	PID           uint32
	UID           uint32

	KernelTimestampNS uint64
	CgroupID          uint64
	RemoteAddress     [net.IPv6len]byte
	Task              [16]byte
}

type udpEventPayload struct {
	ObservedAt        time.Time
	EventType         string
	Protocol          string
	AddressFamily     string
	KernelTimestampNS uint64
	PID               uint32
	UID               uint32
	CgroupID          uint64
	Comm              string
	Remote            tcpLifecycleEndpointPayload
}

func decodeUDPEventPayload(rawSample []byte, observedAt time.Time) (udpEventPayload, error) {
	if len(rawSample) != kernelUDPEventBinarySize {
		return udpEventPayload{}, fmt.Errorf(
			"unexpected UDP event size %d; want %d",
			len(rawSample),
			kernelUDPEventBinarySize,
		)
	}

	var event kernelUDPEvent
	if err := binary.Read(
		bytes.NewReader(rawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		return udpEventPayload{}, fmt.Errorf("decode UDP event: %w", err)
	}

	if err := validateKernelUDPEvent(event); err != nil {
		return udpEventPayload{}, err
	}

	remotePort := event.RemotePort
	return udpEventPayload{
		ObservedAt:        observedAt,
		EventType:         udpEventTypeSend,
		Protocol:          udpProtocol,
		AddressFamily:     conv.ToAddressFamily(int(event.AddressFamily)),
		KernelTimestampNS: event.KernelTimestampNS,
		PID:               event.PID,
		UID:               event.UID,
		CgroupID:          event.CgroupID,
		Comm:              unix.ByteSliceToString(event.Task[:]),
		Remote: tcpLifecycleEndpointPayload{
			IP:   event.remoteIP(),
			Port: &remotePort,
		},
	}, nil
}

func validateKernelUDPEvent(event kernelUDPEvent) error {
	if event.ABIVersion != kernelUDPEventABIVersion {
		return fmt.Errorf("unsupported UDP event ABI version %d", event.ABIVersion)
	}
	if event.EventType != kernelUDPEventTypeSend {
		return fmt.Errorf("unsupported UDP event type %d", event.EventType)
	}
	if event.PID == 0 {
		return fmt.Errorf("UDP event has PID zero")
	}
	if event.KernelTimestampNS == 0 {
		return fmt.Errorf("UDP event has kernel timestamp zero")
	}
	if event.RemotePort == 0 {
		return fmt.Errorf("UDP event has remote port zero")
	}

	switch event.AddressFamily {
	case unix.AF_INET:
		if event.AddressLength != net.IPv4len {
			return fmt.Errorf(
				"UDP IPv4 address length is %d; want %d",
				event.AddressLength,
				net.IPv4len,
			)
		}
		for _, value := range event.RemoteAddress[net.IPv4len:] {
			if value != 0 {
				return fmt.Errorf("UDP IPv4 address has non-zero padding")
			}
		}
	case unix.AF_INET6:
		if event.AddressLength != net.IPv6len {
			return fmt.Errorf(
				"UDP IPv6 address length is %d; want %d",
				event.AddressLength,
				net.IPv6len,
			)
		}
	default:
		return fmt.Errorf("unsupported UDP address family %d", event.AddressFamily)
	}

	return nil
}

func (event kernelUDPEvent) remoteIP() net.IP {
	switch event.AddressLength {
	case net.IPv4len:
		ip := make(net.IP, net.IPv4len)
		copy(ip, event.RemoteAddress[:net.IPv4len])
		return ip
	case net.IPv6len:
		ip := make(net.IP, net.IPv6len)
		copy(ip, event.RemoteAddress[:])
		return ip
	default:
		return nil
	}
}
