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

type udpTableOutput struct {
	writer io.Writer
	mu     sync.Mutex
}

func newUDPTableOutputWithWriter(writer io.Writer) *udpTableOutput {
	return &udpTableOutput{writer: writer}
}

func (output *udpTableOutput) PrintHeader() error {
	output.mu.Lock()
	defer output.mu.Unlock()

	if _, err := fmt.Fprintf(
		output.writer,
		"%-9s %-12s %-6s %-16s %-18s %-40s\n",
		"TIME",
		"EVENT",
		"PID",
		"PROCESS",
		"AF",
		"REMOTE",
	); err != nil {
		return fmt.Errorf("write UDP table header: %w", err)
	}
	return nil
}

func (output *udpTableOutput) WriteEvent(event udpEventPayload) error {
	output.mu.Lock()
	defer output.mu.Unlock()

	if _, err := fmt.Fprintf(
		output.writer,
		"%-9s %-12s %-6d %-16s %-18s %-40s\n",
		event.ObservedAt.Format(tcpLifecycleTableTimeLayout),
		sanitizeTerminalField(event.EventType),
		event.PID,
		sanitizeTerminalField(event.Comm),
		sanitizeTerminalField(event.AddressFamily),
		sanitizeTerminalField(formatUDPRemote(event.Remote)),
	); err != nil {
		return fmt.Errorf("write UDP table event: %w", err)
	}
	return nil
}

func formatUDPRemote(endpoint tcpLifecycleEndpointPayload) string {
	if endpoint.IP == nil || endpoint.Port == nil {
		return "-"
	}
	return net.JoinHostPort(
		endpoint.IP.String(),
		strconv.Itoa(int(*endpoint.Port)),
	)
}
