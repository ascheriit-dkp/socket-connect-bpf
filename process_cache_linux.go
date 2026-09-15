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

import (
	"bytes"
	"container/list"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const maxProcessCacheEntries = 65536

type processSnapshot struct {
	TGID              uint32
	TID               uint32
	UID               uint32
	GID               uint32
	ExecTimestampNS   uint64
	ExitTimestampNS   uint64
	CgroupID          uint64
	Comm              string
	Executable        string
	Arguments         string
	User              string
}

type processCacheLookups struct {
	executable func(int) string
	arguments  func(int) string
	username   func(uint32) string
}

type processCacheEntry struct {
	snapshot processSnapshot
}

type processCache struct {
	mu               sync.Mutex
	maxEntries       int
	includeArguments bool
	entries          map[uint32]*list.Element
	lru              list.List
	lookups          processCacheLookups
}

func newProcessCache(includeArguments bool) *processCache {
	return newProcessCacheWithLookups(
		includeArguments,
		maxProcessCacheEntries,
		processCacheLookups{
			executable: lookupProcessExecutable,
			arguments:  lookupProcessArguments,
			username:   lookupProcessUsername,
		},
	)
}

func newProcessCacheWithLookups(
	includeArguments bool,
	maxEntries int,
	lookups processCacheLookups,
) *processCache {
	if maxEntries < 0 {
		maxEntries = 0
	}

	return &processCache{
		maxEntries:       maxEntries,
		includeArguments: includeArguments,
		entries:          make(map[uint32]*list.Element),
		lookups:          lookups,
	}
}

func (cache *processCache) Observe(event processEvent) {
	switch event.EventType {
	case kernelProcessEventTypeExec:
		cache.observeExec(event)
	case kernelProcessEventTypeExit:
		cache.observeExit(event)
	}
}

func (cache *processCache) observeExec(event processEvent) {
	if cache.maxEntries == 0 {
		return
	}

	snapshot := processSnapshot{
		TGID:            event.TGID,
		TID:             event.TID,
		UID:             event.UID,
		GID:             event.GID,
		ExecTimestampNS: event.KernelTimestampNS,
		CgroupID:        event.CgroupID,
		Comm:            event.Comm,
		Executable:      cache.lookups.executable(int(event.TGID)),
		User:            cache.lookups.username(event.UID),
	}

	if cache.includeArguments {
		snapshot.Arguments = cache.lookups.arguments(int(event.TGID))
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if existing, ok := cache.entries[event.TGID]; ok {
		existing.Value.(*processCacheEntry).snapshot = snapshot
		cache.lru.MoveToBack(existing)
		return
	}

	element := cache.lru.PushBack(&processCacheEntry{snapshot: snapshot})
	cache.entries[event.TGID] = element

	for len(cache.entries) > cache.maxEntries {
		oldest := cache.lru.Front()
		if oldest == nil {
			break
		}

		entry := oldest.Value.(*processCacheEntry)
		delete(cache.entries, entry.snapshot.TGID)
		cache.lru.Remove(oldest)
	}
}

func (cache *processCache) observeExit(event processEvent) {
	if event.TID != event.TGID {
		return
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	element, ok := cache.entries[event.TGID]
	if !ok {
		return
	}

	entry := element.Value.(*processCacheEntry)
	if event.KernelTimestampNS < entry.snapshot.ExecTimestampNS {
		return
	}

	entry.snapshot.ExitTimestampNS = event.KernelTimestampNS
	cache.lru.MoveToBack(element)
}

func (cache *processCache) Lookup(
	pid uint32,
	uid uint32,
	comm string,
	kernelTimestampNS uint64,
) (processSnapshot, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	element, ok := cache.entries[pid]
	if !ok {
		return processSnapshot{}, false
	}

	snapshot := element.Value.(*processCacheEntry).snapshot

	if snapshot.UID != uid {
		return processSnapshot{}, false
	}
	if snapshot.Comm != "" && comm != "" && snapshot.Comm != comm {
		return processSnapshot{}, false
	}
	if kernelTimestampNS != 0 && snapshot.ExecTimestampNS > kernelTimestampNS {
		return processSnapshot{}, false
	}
	if snapshot.ExitTimestampNS != 0 &&
		kernelTimestampNS > snapshot.ExitTimestampNS {
		return processSnapshot{}, false
	}

	cache.lru.MoveToBack(element)
	return snapshot, true
}

func (cache *processCache) Len() int {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}

func lookupProcessExecutable(pid int) string {
	target, err := os.Readlink(
		filepath.Join("/proc", strconv.Itoa(pid), "exe"),
	)
	if err != nil {
		return ""
	}

	return filepath.Clean(target)
}

func lookupProcessArguments(pid int) string {
	data, err := os.ReadFile(
		filepath.Join("/proc", strconv.Itoa(pid), "cmdline"),
	)
	if err != nil || len(data) == 0 {
		return ""
	}

	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return ""
	}

	parts := strings.Split(string(data), "\x00")
	if len(parts) <= 1 {
		return ""
	}

	return strings.Join(parts[1:], " ")
}

func lookupProcessUsername(uid uint32) string {
	uidText := strconv.FormatUint(uint64(uid), 10)
	if info, err := user.LookupId(uidText); err == nil {
		return info.Username
	}

	return uidText
}
