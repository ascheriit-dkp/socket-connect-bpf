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

const tcpLifecycleOutputSchemaVersion = 2

const (
	tcpLifecycleResultSuccess = "success"
	tcpLifecycleResultFailed  = "failed"
)

type tcpLifecycleNDJSONOutput struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

type tcpLifecycleNDJSONEvent struct {
	SchemaVersion        int                        `json:"schema_version"`
	EventType            string                     `json:"event_type"`
	ConnectionID         uint64                     `json:"connection_id"`
	ObservedAt           string                     `json:"observed_at"`
	KernelTimestampNS    uint64                     `json:"kernel_timestamp_ns"`
	Protocol             string                     `json:"protocol"`
	AddressFamily        string                     `json:"address_family"`
	Process              tcpLifecycleNDJSONProcess  `json:"process"`
	Local                tcpLifecycleNDJSONEndpoint `json:"local"`
	Remote               tcpLifecycleNDJSONEndpoint `json:"remote"`
	ASN                   *tcpLifecycleNDJSONASN     `json:"asn,omitempty"`
	Result               string                     `json:"result,omitempty"`
	FailureSource        string                     `json:"failure_source,omitempty"`
	Errno                *int32                     `json:"errno,omitempty"`
	Error                string                     `json:"error,omitempty"`
	ConnectLatencyNS     *uint64                    `json:"connect_latency_ns,omitempty"`
	ConnectionDurationNS *uint64                    `json:"connection_duration_ns,omitempty"`
}

type tcpLifecycleNDJSONProcess struct {
	PID        uint32 `json:"pid"`
	UID        uint32 `json:"uid"`
	Comm       string `json:"comm,omitempty"`
	Executable string `json:"executable,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	User       string `json:"user,omitempty"`
}

type tcpLifecycleNDJSONEndpoint struct {
	IP   string  `json:"ip,omitempty"`
	Port *uint16 `json:"port,omitempty"`
}

type tcpLifecycleNDJSONASN struct {
	Number uint32 `json:"number"`
	Name   string `json:"name,omitempty"`
}

func newTCPLifecycleNDJSONOutputWithWriter(
	writer io.Writer,
) *tcpLifecycleNDJSONOutput {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)

	return &tcpLifecycleNDJSONOutput{
		encoder: encoder,
	}
}

func (output *tcpLifecycleNDJSONOutput) WriteEvent(
	event tcpLifecycleEventPayload,
) error {
	output.mu.Lock()
	defer output.mu.Unlock()

	jsonEvent, err := newTCPLifecycleNDJSONEvent(event)
	if err != nil {
		return err
	}

	if err := output.encoder.Encode(jsonEvent); err != nil {
		return fmt.Errorf("write TCP lifecycle NDJSON event: %w", err)
	}

	return nil
}

func newTCPLifecycleNDJSONEvent(
	event tcpLifecycleEventPayload,
) (tcpLifecycleNDJSONEvent, error) {
	jsonEvent := tcpLifecycleNDJSONEvent{
		SchemaVersion:     tcpLifecycleOutputSchemaVersion,
		EventType:         event.EventType,
		ConnectionID:      event.ConnectionID,
		ObservedAt:        event.ObservedAt.UTC().Format(time.RFC3339Nano),
		KernelTimestampNS: event.KernelTimestampNS,
		Protocol:          event.Protocol,
		AddressFamily:     event.AddressFamily,
		Process: tcpLifecycleNDJSONProcess{
			PID:        event.PID,
			UID:        event.UID,
			Comm:       event.Comm,
			Executable: event.ProcessPath,
			Arguments:  event.ProcessArgs,
			User:       event.User,
		},
		Local:  newTCPLifecycleNDJSONEndpoint(event.Local),
		Remote: newTCPLifecycleNDJSONEndpoint(event.Remote),
	}

	if event.ASN != nil {
		jsonEvent.ASN = &tcpLifecycleNDJSONASN{
			Number: event.ASN.Number,
			Name:   event.ASN.Name,
		}
	}

	switch event.EventType {
	case tcpLifecycleEventTypeConnectAttempt:
	case tcpLifecycleEventTypeEstablished:
		jsonEvent.Result = tcpLifecycleResultSuccess
		jsonEvent.ConnectLatencyNS = cloneUint64Pointer(
			event.ConnectLatencyNS,
		)
	case tcpLifecycleEventTypeConnectFailed:
		jsonEvent.Result = tcpLifecycleResultFailed
		jsonEvent.FailureSource = event.FailureSource
		jsonEvent.Errno = cloneInt32Pointer(event.Errno)
		jsonEvent.Error = event.Error
		jsonEvent.ConnectLatencyNS = cloneUint64Pointer(
			event.ConnectLatencyNS,
		)
	case tcpLifecycleEventTypeClosed:
		jsonEvent.ConnectionDurationNS = cloneUint64Pointer(
			event.ConnectionDurationNS,
		)
	default:
		return tcpLifecycleNDJSONEvent{}, fmt.Errorf(
			"encode TCP lifecycle NDJSON event: unsupported event type %q",
			event.EventType,
		)
	}

	return jsonEvent, nil
}

func newTCPLifecycleNDJSONEndpoint(
	endpoint tcpLifecycleEndpointPayload,
) tcpLifecycleNDJSONEndpoint {
	jsonEndpoint := tcpLifecycleNDJSONEndpoint{
		Port: cloneUint16Pointer(endpoint.Port),
	}

	if endpoint.IP != nil {
		jsonEndpoint.IP = endpoint.IP.String()
	}

	return jsonEndpoint
}

func cloneUint16Pointer(value *uint16) *uint16 {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}

func cloneUint64Pointer(value *uint64) *uint64 {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}

func cloneInt32Pointer(value *int32) *int32 {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}
