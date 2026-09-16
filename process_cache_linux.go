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
	TGID            uint32
	TID             uint32
	UID             uint32
	GID             uint32
	ExecTimestampNS uint64
	ExitTimestampNS uint64
	CgroupID        uint64
	Comm            string
	Executable      string
	Arguments       string
	User            string
	Context         processContextSnapshot
}

type processCacheLookups struct {
	executable func(int) string
	arguments  func(int) string
	username   func(uint32) string
	context    func(int) processContextSnapshot
}

type processCacheKey struct {
	TGID            uint32
	ExecTimestampNS uint64
}

type processCacheEntry struct {
	key      processCacheKey
	snapshot processSnapshot
}

type processCache struct {
	mu               sync.Mutex
	maxEntries       int
	includeArguments bool
	entries          map[processCacheKey]*list.Element
	generations      map[uint32][]processCacheKey
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
			context:    lookupProcessContext,
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
		entries:          make(map[processCacheKey]*list.Element),
		generations:      make(map[uint32][]processCacheKey),
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

	if cache.lookups.context != nil {
		snapshot.Context = cache.lookups.context(int(event.TGID))
	}

	if cache.includeArguments {
		snapshot.Arguments = cache.lookups.arguments(int(event.TGID))
	}

	key := processCacheKey{
		TGID:            event.TGID,
		ExecTimestampNS: event.KernelTimestampNS,
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if existing, ok := cache.entries[key]; ok {
		existing.Value.(*processCacheEntry).snapshot = snapshot
		cache.lru.MoveToBack(existing)
		return
	}

	element := cache.lru.PushBack(&processCacheEntry{
		key:      key,
		snapshot: snapshot,
	})
	cache.entries[key] = element
	cache.generations[event.TGID] = append(
		cache.generations[event.TGID],
		key,
	)

	for len(cache.entries) > cache.maxEntries {
		cache.evictOldestLocked()
	}
}

func (cache *processCache) observeExit(event processEvent) {
	if event.TID != event.TGID {
		return
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	keys := cache.generations[event.TGID]
	for index := len(keys) - 1; index >= 0; index-- {
		element, ok := cache.entries[keys[index]]
		if !ok {
			continue
		}

		entry := element.Value.(*processCacheEntry)
		if event.KernelTimestampNS < entry.snapshot.ExecTimestampNS {
			continue
		}
		if entry.snapshot.ExitTimestampNS != 0 {
			continue
		}

		entry.snapshot.ExitTimestampNS = event.KernelTimestampNS
		cache.lru.MoveToBack(element)
		return
	}
}

// Lookup returns the process generation that was alive at kernelTimestampNS.
// trackedPID is true when the cache has observed at least one exec generation
// for the PID. Callers use it to avoid falling back to /proc when that fallback
// could accidentally read metadata from a newer PID generation.
func (cache *processCache) Lookup(
	pid uint32,
	uid uint32,
	comm string,
	kernelTimestampNS uint64,
) (snapshot processSnapshot, found bool, trackedPID bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	keys := cache.generations[pid]
	if len(keys) == 0 {
		return processSnapshot{}, false, false
	}

	for index := len(keys) - 1; index >= 0; index-- {
		element, ok := cache.entries[keys[index]]
		if !ok {
			continue
		}

		candidate := element.Value.(*processCacheEntry).snapshot
		if candidate.ExecTimestampNS > kernelTimestampNS {
			continue
		}
		if candidate.ExitTimestampNS != 0 &&
			kernelTimestampNS > candidate.ExitTimestampNS {
			continue
		}
		if candidate.UID != uid {
			continue
		}
		if candidate.Comm != "" && comm != "" && candidate.Comm != comm {
			continue
		}

		cache.lru.MoveToBack(element)
		return candidate, true, true
	}

	return processSnapshot{}, false, true
}

func (cache *processCache) Len() int {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}

func (cache *processCache) evictOldestLocked() {
	oldest := cache.lru.Front()
	if oldest == nil {
		return
	}

	entry := oldest.Value.(*processCacheEntry)
	delete(cache.entries, entry.key)
	cache.lru.Remove(oldest)

	keys := cache.generations[entry.key.TGID]
	for index, key := range keys {
		if key != entry.key {
			continue
		}

		keys = append(keys[:index], keys[index+1:]...)
		break
	}

	if len(keys) == 0 {
		delete(cache.generations, entry.key.TGID)
	} else {
		cache.generations[entry.key.TGID] = keys
	}
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

	return redactProcessArguments(strings.Join(parts[1:], " "))
}

func lookupProcessUsername(uid uint32) string {
	uidText := strconv.FormatUint(uint64(uid), 10)
	if info, err := user.LookupId(uidText); err == nil {
		return info.Username
	}

	return uidText
}
