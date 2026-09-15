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
	"strings"
	"testing"
)

func TestDecodeProcessEvent(t *testing.T) {
	kernelEvent := kernelProcessEvent{
		ABIVersion:        kernelProcessEventABIVersion,
		EventType:         kernelProcessEventTypeExec,
		TGID:              1234,
		TID:               1234,
		UID:               1000,
		GID:               1001,
		KernelTimestampNS: 123456789,
		CgroupID:          42,
	}
	copy(kernelEvent.Task[:], []byte("curl"))

	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, kernelEvent); err != nil {
		t.Fatalf("encoding process event: %v", err)
	}

	if buffer.Len() != kernelProcessEventBinarySize {
		t.Fatalf(
			"encoded process event size = %d; want %d",
			buffer.Len(),
			kernelProcessEventBinarySize,
		)
	}

	event, err := decodeProcessEvent(buffer.Bytes())
	if err != nil {
		t.Fatalf("decoding process event: %v", err)
	}

	if event.EventType != kernelProcessEventTypeExec {
		t.Fatalf("unexpected event type: %d", event.EventType)
	}
	if event.TGID != 1234 || event.TID != 1234 {
		t.Fatalf("unexpected process IDs: tgid=%d tid=%d", event.TGID, event.TID)
	}
	if event.UID != 1000 || event.GID != 1001 {
		t.Fatalf("unexpected credentials: uid=%d gid=%d", event.UID, event.GID)
	}
	if event.KernelTimestampNS != 123456789 {
		t.Fatalf("unexpected timestamp: %d", event.KernelTimestampNS)
	}
	if event.CgroupID != 42 {
		t.Fatalf("unexpected cgroup ID: %d", event.CgroupID)
	}
	if event.Comm != "curl" {
		t.Fatalf("unexpected comm: %q", event.Comm)
	}
}

func TestDecodeProcessEventRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name  string
		event kernelProcessEvent
		want  string
	}{
		{
			name: "abi",
			event: kernelProcessEvent{
				ABIVersion:        99,
				EventType:         kernelProcessEventTypeExec,
				TGID:              1,
				TID:               1,
				KernelTimestampNS: 1,
			},
			want: "ABI version",
		},
		{
			name: "event type",
			event: kernelProcessEvent{
				ABIVersion:        kernelProcessEventABIVersion,
				EventType:         99,
				TGID:              1,
				TID:               1,
				KernelTimestampNS: 1,
			},
			want: "event type",
		},
		{
			name: "tgid",
			event: kernelProcessEvent{
				ABIVersion:        kernelProcessEventABIVersion,
				EventType:         kernelProcessEventTypeExec,
				TID:               1,
				KernelTimestampNS: 1,
			},
			want: "TGID zero",
		},
		{
			name: "reserved",
			event: kernelProcessEvent{
				ABIVersion:        kernelProcessEventABIVersion,
				EventType:         kernelProcessEventTypeExit,
				TGID:              1,
				TID:               1,
				KernelTimestampNS: 1,
				Reserved1:         1,
			},
			want: "reserved fields",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := binary.Write(&buffer, binary.LittleEndian, test.event); err != nil {
				t.Fatalf("encoding process event: %v", err)
			}

			_, err := decodeProcessEvent(buffer.Bytes())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v; want substring %q", err, test.want)
			}
		})
	}

	if _, err := decodeProcessEvent(make([]byte, kernelProcessEventBinarySize-1)); err == nil {
		t.Fatal("short process event was accepted")
	}
}
