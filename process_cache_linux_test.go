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

func TestProcessCachePreservesPIDGenerations(t *testing.T) {
	generation := "old"
	cache := newProcessCacheWithLookups(
		true,
		4,
		processCacheLookups{
			executable: func(int) string { return "/usr/bin/" + generation },
			arguments:  func(int) string { return "--generation=" + generation },
			username:   func(uint32) string { return "alice" },
		},
	)

	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExec,
		TGID:              1234,
		TID:               1234,
		UID:               1000,
		GID:               1000,
		KernelTimestampNS: 100,
		CgroupID:          10,
		Comm:              "old",
	})
	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExit,
		TGID:              1234,
		TID:               1234,
		UID:               1000,
		GID:               1000,
		KernelTimestampNS: 150,
		CgroupID:          10,
		Comm:              "old",
	})

	generation = "new"
	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExec,
		TGID:              1234,
		TID:               1234,
		UID:               1000,
		GID:               1000,
		KernelTimestampNS: 200,
		CgroupID:          20,
		Comm:              "new",
	})

	oldSnapshot, found, tracked := cache.Lookup(1234, 1000, "old", 120)
	if !found || !tracked {
		t.Fatalf("old process generation not found: found=%v tracked=%v", found, tracked)
	}
	if oldSnapshot.Executable != "/usr/bin/old" {
		t.Fatalf("old executable = %q", oldSnapshot.Executable)
	}
	if oldSnapshot.Arguments != "--generation=old" {
		t.Fatalf("old arguments = %q", oldSnapshot.Arguments)
	}
	if oldSnapshot.ExitTimestampNS != 150 {
		t.Fatalf("old exit timestamp = %d; want 150", oldSnapshot.ExitTimestampNS)
	}

	newSnapshot, found, tracked := cache.Lookup(1234, 1000, "new", 220)
	if !found || !tracked {
		t.Fatalf("new process generation not found: found=%v tracked=%v", found, tracked)
	}
	if newSnapshot.Executable != "/usr/bin/new" {
		t.Fatalf("new executable = %q", newSnapshot.Executable)
	}
	if newSnapshot.CgroupID != 20 {
		t.Fatalf("new cgroup ID = %d; want 20", newSnapshot.CgroupID)
	}

	_, found, tracked = cache.Lookup(1234, 1000, "old", 175)
	if found || !tracked {
		t.Fatalf("gap lookup: found=%v tracked=%v; want false,true", found, tracked)
	}
}

func TestProcessCacheIgnoresThreadExit(t *testing.T) {
	cache := newProcessCacheWithLookups(
		false,
		2,
		processCacheLookups{
			executable: func(int) string { return "/usr/bin/test" },
			arguments:  func(int) string { return "" },
			username:   func(uint32) string { return "user" },
		},
	)

	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExec,
		TGID:              50,
		TID:               50,
		UID:               1000,
		KernelTimestampNS: 100,
		Comm:              "test",
	})
	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExit,
		TGID:              50,
		TID:               51,
		UID:               1000,
		KernelTimestampNS: 120,
		Comm:              "test",
	})

	snapshot, found, _ := cache.Lookup(50, 1000, "test", 130)
	if !found {
		t.Fatal("thread exit incorrectly ended process generation")
	}
	if snapshot.ExitTimestampNS != 0 {
		t.Fatalf("exit timestamp = %d; want 0", snapshot.ExitTimestampNS)
	}
}

func TestProcessCacheBoundsEntries(t *testing.T) {
	cache := newProcessCacheWithLookups(
		false,
		2,
		processCacheLookups{
			executable: func(int) string { return "process" },
			arguments:  func(int) string { return "" },
			username:   func(uint32) string { return "user" },
		},
	)

	for pid := uint32(1); pid <= 3; pid++ {
		cache.Observe(processEvent{
			EventType:         kernelProcessEventTypeExec,
			TGID:              pid,
			TID:               pid,
			UID:               1000,
			KernelTimestampNS: uint64(pid * 10),
			Comm:              "test",
		})
	}

	if cache.Len() != 2 {
		t.Fatalf("cache length = %d; want 2", cache.Len())
	}

	_, found, tracked := cache.Lookup(1, 1000, "test", 10)
	if found || tracked {
		t.Fatalf("evicted PID remains tracked: found=%v tracked=%v", found, tracked)
	}
}

func TestProcessCacheSkipsArgumentsWhenDisabled(t *testing.T) {
	argumentCalls := 0
	cache := newProcessCacheWithLookups(
		false,
		1,
		processCacheLookups{
			executable: func(int) string { return "/usr/bin/test" },
			arguments: func(int) string {
				argumentCalls++
				return "secret"
			},
			username: func(uint32) string { return "user" },
		},
	)

	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExec,
		TGID:              99,
		TID:               99,
		UID:               1000,
		KernelTimestampNS: 1,
		Comm:              "test",
	})

	if argumentCalls != 0 {
		t.Fatalf("argument lookup called %d times; want 0", argumentCalls)
	}
}

func TestTCPLifecycleEnricherUsesProcessCache(t *testing.T) {
	cache := newProcessCacheWithLookups(
		true,
		2,
		processCacheLookups{
			executable: func(int) string { return "/usr/bin/curl" },
			arguments:  func(int) string { return "--silent" },
			username:   func(uint32) string { return "alice" },
		},
	)
	cache.Observe(processEvent{
		EventType:         kernelProcessEventTypeExec,
		TGID:              1234,
		TID:               1234,
		UID:               1000,
		GID:               1000,
		KernelTimestampNS: 100,
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

	if payload.ProcessPath != "/usr/bin/curl" {
		t.Fatalf("process path = %q", payload.ProcessPath)
	}
	if payload.ProcessArgs != "--silent" {
		t.Fatalf("process arguments = %q", payload.ProcessArgs)
	}
	if payload.User != "alice" {
		t.Fatalf("user = %q", payload.User)
	}
}
