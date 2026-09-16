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
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

const udpOutputSchemaVersion = 3

type udpNDJSONOutput struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

type udpNDJSONEvent struct {
	SchemaVersion     int                        `json:"schema_version"`
	EventType         string                     `json:"event_type"`
	ObservedAt        string                     `json:"observed_at"`
	KernelTimestampNS uint64                     `json:"kernel_timestamp_ns"`
	Protocol          string                     `json:"protocol"`
	AddressFamily     string                     `json:"address_family"`
	Process           tcpLifecycleNDJSONProcess  `json:"process"`
	Remote            tcpLifecycleNDJSONEndpoint `json:"remote"`
	ASN               *tcpLifecycleNDJSONASN     `json:"asn,omitempty"`
	DNS               *dnsNDJSONPayload          `json:"dns,omitempty"`
}

func newUDPNDJSONOutputWithWriter(writer io.Writer) *udpNDJSONOutput {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &udpNDJSONOutput{encoder: encoder}
}

func (output *udpNDJSONOutput) PrintHeader() error {
	return nil
}

func (output *udpNDJSONOutput) WriteEvent(event udpEventPayload) error {
	output.mu.Lock()
	defer output.mu.Unlock()

	jsonEvent := newUDPNDJSONEvent(event)
	if err := output.encoder.Encode(jsonEvent); err != nil {
		return fmt.Errorf("write UDP NDJSON event: %w", err)
	}
	return nil
}

func newUDPNDJSONEvent(event udpEventPayload) udpNDJSONEvent {
	process := tcpLifecycleNDJSONProcess{
		PID:            event.PID,
		UID:            event.UID,
		GID:            cloneUint32Pointer(event.GID),
		Comm:           event.Comm,
		Executable:     event.ProcessPath,
		Arguments:      event.ProcessArgs,
		User:           event.User,
		StartTimeTicks: cloneUint64Pointer(event.ProcessStartTimeTicks),
		Parent:         newTCPLifecycleNDJSONParent(event.Parent),
		Cgroup:         newTCPLifecycleNDJSONCgroup(event.Cgroup),
		Namespaces:     newTCPLifecycleNDJSONNamespaces(event.Namespaces),
		Container:      newTCPLifecycleNDJSONContainer(event.Container),
	}

	remote := tcpLifecycleNDJSONEndpoint{
		Port: cloneUint16Pointer(event.Remote.Port),
	}
	if event.Remote.IP != nil {
		remote.IP = event.Remote.IP.String()
	}

	jsonEvent := udpNDJSONEvent{
		SchemaVersion:     udpOutputSchemaVersion,
		EventType:         event.EventType,
		ObservedAt:        event.ObservedAt.UTC().Format(time.RFC3339Nano),
		KernelTimestampNS: event.KernelTimestampNS,
		Protocol:          event.Protocol,
		AddressFamily:     event.AddressFamily,
		Process:           process,
		Remote:            remote,
		DNS:               dnsNDJSONForRemote(remote.IP),
	}
	if event.ASN != nil {
		jsonEvent.ASN = &tcpLifecycleNDJSONASN{
			Number: event.ASN.Number,
			Name:   event.ASN.Name,
		}
	}

	return jsonEvent
}
