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
	"io"
	"net"
	"strconv"
	"sync"
)

const tcpLifecycleTableTimeLayout = "15:04:05"

type tcpLifecycleTableOutput struct {
	writer io.Writer
	mu     sync.Mutex
}

func newTCPLifecycleTableOutputWithWriter(
	writer io.Writer,
) *tcpLifecycleTableOutput {
	return &tcpLifecycleTableOutput{
		writer: writer,
	}
}

func (output *tcpLifecycleTableOutput) PrintHeader() error {
	output.mu.Lock()
	defer output.mu.Unlock()

	if _, err := fmt.Fprintf(
		output.writer,
		"%-9s %-20s %-6s %-32s %-16s %-40s %-40s %-8s %-24s %-12s %-12s %s\n",
		"TIME",
		"EVENT",
		"PID",
		"PROCESS",
		"USER",
		"LOCAL",
		"REMOTE",
		"RESULT",
		"ERROR",
		"CONNECT_NS",
		"DURATION_NS",
		"AS-INFO",
	); err != nil {
		return fmt.Errorf("write TCP lifecycle table header: %w", err)
	}

	return nil
}

func (output *tcpLifecycleTableOutput) WriteEvent(
	event tcpLifecycleEventPayload,
) error {
	result, err := tcpLifecycleTableResult(event.EventType)
	if err != nil {
		return err
	}

	output.mu.Lock()
	defer output.mu.Unlock()

	if _, err := fmt.Fprintf(
		output.writer,
		"%-9s %-20s %-6d %-32s %-16s %-40s %-40s %-8s %-24s %-12s %-12s %s\n",
		event.ObservedAt.Format(tcpLifecycleTableTimeLayout),
		sanitizeTerminalField(event.EventType),
		event.PID,
		formatTCPLifecycleTableProcess(event),
		sanitizeTerminalField(formatTCPLifecycleTableOptionalText(event.User)),
		sanitizeTerminalField(formatTCPLifecycleTableEndpoint(event.Local)),
		sanitizeTerminalField(formatTCPLifecycleTableEndpoint(event.Remote)),
		result,
		formatTCPLifecycleTableError(event.Error),
		formatTCPLifecycleTableOptionalUint64(event.ConnectLatencyNS),
		formatTCPLifecycleTableOptionalUint64(event.ConnectionDurationNS),
		formatTCPLifecycleTableASN(event.ASN),
	); err != nil {
		return fmt.Errorf("write TCP lifecycle table event: %w", err)
	}

	return nil
}

func tcpLifecycleTableResult(eventType string) (string, error) {
	switch eventType {
	case tcpLifecycleEventTypeConnectAttempt,
		tcpLifecycleEventTypeClosed:
		return "-", nil
	case tcpLifecycleEventTypeEstablished:
		return tcpLifecycleResultSuccess, nil
	case tcpLifecycleEventTypeConnectFailed:
		return tcpLifecycleResultFailed, nil
	default:
		return "", fmt.Errorf(
			"write TCP lifecycle table event: unsupported event type %q",
			eventType,
		)
	}
}

func formatTCPLifecycleTableProcess(
	event tcpLifecycleEventPayload,
) string {
	process := event.ProcessPath
	if process == "" {
		process = event.Comm
	}

	if event.ProcessArgs != "" {
		if process != "" {
			process += " "
		}
		process += event.ProcessArgs
	}

	return sanitizeTerminalField(formatTCPLifecycleTableOptionalText(process))
}

func formatTCPLifecycleTableEndpoint(
	endpoint tcpLifecycleEndpointPayload,
) string {
	hasIP := endpoint.IP != nil
	hasPort := endpoint.Port != nil

	switch {
	case hasIP && hasPort:
		return net.JoinHostPort(
			endpoint.IP.String(),
			strconv.Itoa(int(*endpoint.Port)),
		)
	case hasIP:
		return endpoint.IP.String()
	case hasPort:
		return ":" + strconv.Itoa(int(*endpoint.Port))
	default:
		return "-"
	}
}

func formatTCPLifecycleTableError(value string) string {
	if value == "" {
		return "-"
	}

	return sanitizeTerminalField(value)
}

func formatTCPLifecycleTableOptionalText(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

func formatTCPLifecycleTableOptionalUint64(value *uint64) string {
	if value == nil {
		return "-"
	}

	return strconv.FormatUint(*value, 10)
}

func formatTCPLifecycleTableASN(value *tcpLifecycleASNPayload) string {
	if value == nil {
		return "-"
	}

	text := "AS" + strconv.FormatUint(uint64(value.Number), 10)
	if value.Name != "" {
		text += " (" + value.Name + ")"
	}

	return sanitizeTerminalField(text)
}
