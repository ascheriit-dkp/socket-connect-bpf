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
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func readProcessEvents(reader *ringbuf.Reader, cache *processCache) {
	var record ringbuf.Record

	for {
		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}

			log.Printf("reading process event ring buffer: %s", err)
			return
		}

		event, err := decodeProcessEvent(record.RawSample)
		if err != nil {
			log.Printf("processing process event: %s", err)
			continue
		}

		cache.Observe(event)
	}
}

func reportProcessDroppedEvents(droppedEvents *ebpf.Map) {
	const counterKey uint32 = 0

	var perCPUCounts []uint64
	if err := droppedEvents.Lookup(counterKey, &perCPUCounts); err != nil {
		log.Printf("reading process event loss counter: %s", err)
		return
	}

	var total uint64
	for _, count := range perCPUCounts {
		total += count
	}

	log.Printf("process event loss summary: total=%d", total)
}
