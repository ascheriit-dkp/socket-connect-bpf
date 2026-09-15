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

//go:build linux
// +build linux

package main

import "testing"

func TestTCPLifecycleEnricherPreservesAdvancedProcessContext(t *testing.T) {
	containerID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cache := newProcessCacheWithLookups(
		true,
		4,
		processCacheLookups{
			executable: func(int) string { return "/usr/bin/curl" },
			arguments:  func(int) string { return "--silent" },
			username:   func(uint32) string { return "alice" },
			context: func(int) processContextSnapshot {
				return processContextSnapshot{
					StartTimeTicks:       12345,
					ParentPID:            77,
					ParentStartTimeTicks: 11111,
					CgroupPath:           "/docker/" + containerID,
					Namespaces: processNamespaceSnapshot{
						Cgroup: 1,
						IPC:    2,
						Mount:  3,
						Net:    4,
						PID:    5,
						User:   6,
						UTS:    7,
					},
					Container: &processContainerSnapshot{
						Runtime: "docker",
						ID:      containerID,
					},
				}
			},
		},
	)

	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExec,
		TGID:              1234,
		TID:               1234,
		UID:               1000,
		GID:               1001,
		KernelTimestampNS: 100,
		CgroupID:          999,
		Comm:              "curl",
	})

	enricher := newTCPLifecycleEnricherWithProcessCache(true, cache)
	payload := enricher.Enrich(tcpLifecycleEventPayload{
		EventType:         tcpLifecycleEventTypeConnectAttempt,
		ConnectionID:      1,
		KernelTimestampNS: 120,
		PID:               1234,
		UID:               1000,
		Comm:              "curl",
	})

	if payload.GID == nil || *payload.GID != 1001 {
		t.Fatalf("GID = %v; want 1001", payload.GID)
	}
	if payload.ProcessStartTimeTicks == nil || *payload.ProcessStartTimeTicks != 12345 {
		t.Fatalf("start time = %v; want 12345", payload.ProcessStartTimeTicks)
	}
	if payload.Parent == nil || payload.Parent.PID != 77 ||
		payload.Parent.StartTimeTicks == nil || *payload.Parent.StartTimeTicks != 11111 {
		t.Fatalf("parent = %#v", payload.Parent)
	}
	if payload.Cgroup == nil || payload.Cgroup.ID == nil ||
		*payload.Cgroup.ID != 999 || payload.Cgroup.Path != "/docker/"+containerID {
		t.Fatalf("cgroup = %#v", payload.Cgroup)
	}
	if payload.Namespaces == nil || payload.Namespaces.Net != 4 ||
		payload.Namespaces.PID != 5 {
		t.Fatalf("namespaces = %#v", payload.Namespaces)
	}
	if payload.Container == nil || payload.Container.Runtime != "docker" ||
		payload.Container.ID != containerID {
		t.Fatalf("container = %#v", payload.Container)
	}

	jsonEvent, err := newTCPLifecycleNDJSONEvent(payload)
	if err != nil {
		t.Fatalf("encode NDJSON event: %v", err)
	}
	if jsonEvent.Process.GID == nil || *jsonEvent.Process.GID != 1001 {
		t.Fatalf("NDJSON GID = %v; want 1001", jsonEvent.Process.GID)
	}
	if jsonEvent.Process.Parent == nil || jsonEvent.Process.Parent.PID != 77 {
		t.Fatalf("NDJSON parent = %#v", jsonEvent.Process.Parent)
	}
	if jsonEvent.Process.Cgroup == nil || jsonEvent.Process.Cgroup.ID == nil ||
		*jsonEvent.Process.Cgroup.ID != 999 {
		t.Fatalf("NDJSON cgroup = %#v", jsonEvent.Process.Cgroup)
	}
	if jsonEvent.Process.Namespaces == nil || jsonEvent.Process.Namespaces.Mount != 3 {
		t.Fatalf("NDJSON namespaces = %#v", jsonEvent.Process.Namespaces)
	}
	if jsonEvent.Process.Container == nil || jsonEvent.Process.Container.Runtime != "docker" {
		t.Fatalf("NDJSON container = %#v", jsonEvent.Process.Container)
	}
}

func TestTCPLifecycleEnricherFallsBackToLiveContextForPreExistingProcess(t *testing.T) {
	gid := uint32(2000)
	enricher := newTCPLifecycleEnricherWithLookups(
		false,
		2,
		tcpLifecycleEnrichmentLookups{
			processPath: func(int) string { return "/usr/bin/preexisting" },
			processArgs: func(int) string { return "" },
			username:    func(uint32) string { return "bob" },
			context: func(int) processContextSnapshot {
				return processContextSnapshot{
					GID:            &gid,
					StartTimeTicks: 55,
					ParentPID:      1,
					CgroupPath:     "/user.slice/test.scope",
				}
			},
			asn: func(tcpLifecycleEventPayload) *tcpLifecycleASNPayload { return nil },
		},
	)

	payload := enricher.Enrich(tcpLifecycleEventPayload{
		EventType:         tcpLifecycleEventTypeConnectAttempt,
		ConnectionID:      9,
		KernelTimestampNS: 100,
		PID:               222,
		UID:               1000,
		Comm:              "preexisting",
	})

	if payload.GID == nil || *payload.GID != 2000 {
		t.Fatalf("GID = %v; want 2000", payload.GID)
	}
	if payload.ProcessStartTimeTicks == nil || *payload.ProcessStartTimeTicks != 55 {
		t.Fatalf("start time = %v; want 55", payload.ProcessStartTimeTicks)
	}
	if payload.Parent == nil || payload.Parent.PID != 1 {
		t.Fatalf("parent = %#v", payload.Parent)
	}
	if payload.Cgroup == nil || payload.Cgroup.Path != "/user.slice/test.scope" {
		t.Fatalf("cgroup = %#v", payload.Cgroup)
	}
}
