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
	"io"
	"net"
	"testing"
	"time"
)

func BenchmarkTCPLifecycleTableOutput(b *testing.B) {
	output := newTCPLifecycleTableOutputWithWriter(io.Discard)
	event := benchmarkTCPLifecyclePayload()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if err := output.WriteEvent(event); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPLifecycleNDJSONOutput(b *testing.B) {
	output := newTCPLifecycleNDJSONOutputWithWriter(io.Discard)
	event := benchmarkTCPLifecyclePayload()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if err := output.WriteEvent(event); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkTCPLifecyclePayload() tcpLifecycleEventPayload {
	localPort := uint16(40_000)
	remotePort := uint16(443)
	establishedTimestamp := uint64(1_500)
	connectLatency := uint64(500)

	return tcpLifecycleEventPayload{
		ObservedAt:              time.Unix(1_800_000_000, 123_456_789).UTC(),
		EventType:               tcpLifecycleEventTypeEstablished,
		Protocol:                tcpLifecycleProtocolTCP,
		AddressFamily:           "AF_INET",
		ConnectionID:            42,
		KernelTimestampNS:       1_500,
		AttemptTimestampNS:      1_000,
		EstablishedTimestampNS: &establishedTimestamp,
		PID:                     1234,
		UID:                     1000,
		Comm:                    "curl",
		Local: tcpLifecycleEndpointPayload{
			IP:   net.IPv4(192, 0, 2, 10).To4(),
			Port: &localPort,
		},
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.IPv4(198, 51, 100, 20).To4(),
			Port: &remotePort,
		},
		ConnectLatencyNS: &connectLatency,
	}
}
