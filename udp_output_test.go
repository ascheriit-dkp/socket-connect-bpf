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
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestUDPNDJSONSchemaV3(t *testing.T) {
	var output bytes.Buffer
	writer := newUDPNDJSONOutputWithWriter(&output)
	if err := writer.WriteEvent(testUDPEventPayload()); err != nil {
		t.Fatal(err)
	}

	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}

	if event["schema_version"] != float64(3) {
		t.Fatalf("schema_version = %#v", event["schema_version"])
	}
	if event["event_type"] != udpEventTypeSend || event["protocol"] != udpProtocol {
		t.Fatalf("unexpected event identity: %#v", event)
	}

	process, ok := event["process"].(map[string]any)
	if !ok {
		t.Fatalf("process = %#v", event["process"])
	}
	if process["pid"] != float64(1234) || process["uid"] != float64(1000) {
		t.Fatalf("unexpected process: %#v", process)
	}
	if process["executable"] != "/usr/bin/sender" || process["user"] != "alice" {
		t.Fatalf("unexpected process enrichment: %#v", process)
	}
	cgroup, ok := process["cgroup"].(map[string]any)
	if !ok || cgroup["id"] != float64(99) {
		t.Fatalf("unexpected cgroup: %#v", process["cgroup"])
	}

	remote, ok := event["remote"].(map[string]any)
	if !ok {
		t.Fatalf("remote = %#v", event["remote"])
	}
	if remote["ip"] != "192.0.2.25" || remote["port"] != float64(5353) {
		t.Fatalf("unexpected remote: %#v", remote)
	}
	if _, exists := event["result"]; exists {
		t.Fatal("UDP send must not contain a result field")
	}
	if _, exists := event["connection_id"]; exists {
		t.Fatal("UDP send must not contain a connection_id field")
	}
}

func TestUDPTableSanitizesProcessName(t *testing.T) {
	var output bytes.Buffer
	writer := newUDPTableOutputWithWriter(&output)
	if err := writer.PrintHeader(); err != nil {
		t.Fatal(err)
	}

	event := testUDPEventPayload()
	event.Comm = "bad\nname\t"
	if err := writer.WriteEvent(event); err != nil {
		t.Fatal(err)
	}

	text := output.String()
	if strings.Contains(text, "bad\nname") || strings.Contains(text, "name\t") {
		t.Fatalf("unsafe table output: %q", text)
	}
	if !strings.Contains(text, "192.0.2.25:5353") {
		t.Fatalf("missing remote endpoint: %q", text)
	}
}

func TestNewUDPOutputForFormat(t *testing.T) {
	var output bytes.Buffer
	if _, err := newUDPOutputForFormat(outputFormatTable, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := newUDPOutputForFormat(outputFormatNDJSON, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := newUDPOutputForFormat("xml", &output); err == nil {
		t.Fatal("expected unsupported-format error")
	}
}

func testUDPEventPayload() udpEventPayload {
	port := uint16(5353)
	cgroupID := uint64(99)
	return udpEventPayload{
		ObservedAt:        time.Date(2026, 9, 15, 20, 0, 0, 123, time.UTC),
		EventType:         udpEventTypeSend,
		Protocol:          udpProtocol,
		AddressFamily:     "AF_INET",
		KernelTimestampNS: 123456,
		PID:               1234,
		UID:               1000,
		CgroupID:          99,
		Comm:              "sender",
		ProcessPath:       "/usr/bin/sender",
		User:              "alice",
		Cgroup: &tcpLifecycleCgroupPayload{
			ID: &cgroupID,
		},
		Remote: tcpLifecycleEndpointPayload{
			IP:   net.ParseIP("192.0.2.25").To4(),
			Port: &port,
		},
	}
}
