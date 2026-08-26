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
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	tcpLifecycleDiagnosticMapUpdateFailure uint32 = iota
	tcpLifecycleDiagnosticMissingCorrelation
	tcpLifecycleDiagnosticUnsupportedObservation
)

func setupTCPLifecycleWorkers(filters kernelFilterOptions) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	if err := configureKernelFilters(
		filters,
		kernelFilterMaps{
			config: objs.FilterConfig,
			pids:   objs.PidFilters,
			uids:   objs.UidFilters,
			ports:  objs.PortFilters,
		},
	); err != nil {
		log.Fatalf("configuring kernel filters: %v", err)
	}

	links, err := attachTCPLifecyclePrograms(&objs)
	if err != nil {
		log.Fatal(err)
	}

	reader, err := ringbuf.NewReader(objs.SocketEvents)
	if err != nil {
		closeTCPLifecycleLinks(links)
		log.Fatalf("creating TCP lifecycle ring-buffer reader: %s", err)
	}

	lifecycleOutput, err := newTCPLifecycleOutputForFormat(
		selectedOutputFormat(),
		os.Stdout,
	)
	if err != nil {
		closeRingBufferReader(reader)
		closeTCPLifecycleLinks(links)
		log.Fatal(err)
	}

	if err := lifecycleOutput.PrintHeader(); err != nil {
		closeRingBufferReader(reader)
		closeTCPLifecycleLinks(links)
		log.Fatal(err)
	}

	enricher := newTCPLifecycleEnricher(selectedExtendedOutput())

	go func() {
		<-stopper
		log.Println("received signal, exiting program")
		closeRingBufferReader(reader)
	}()

	readTCPLifecycleEvents(reader, lifecycleOutput, enricher)
	closeRingBufferReader(reader)
	closeTCPLifecycleLinks(links)

	reportDroppedEvents(objs.DroppedEvents)
	reportTCPLifecycleDiagnostics(objs.LifecycleDiagnostics)
}

func attachTCPLifecyclePrograms(objs *bpfObjects) ([]link.Link, error) {
	type attachment struct {
		name   string
		attach func() (link.Link, error)
	}

	attachments := []attachment{
		{
			name: "tcp_v4_connect kprobe",
			attach: func() (link.Link, error) {
				return link.Kprobe(
					"tcp_v4_connect",
					objs.KprobeTcpV4Connect,
					nil,
				)
			},
		},
		{
			name: "tcp_v4_connect kretprobe",
			attach: func() (link.Link, error) {
				return link.Kretprobe(
					"tcp_v4_connect",
					objs.KretprobeTcpV4Connect,
					nil,
				)
			},
		},
		{
			name: "tcp_v6_connect kprobe",
			attach: func() (link.Link, error) {
				return link.Kprobe(
					"tcp_v6_connect",
					objs.KprobeTcpV6Connect,
					nil,
				)
			},
		},
		{
			name: "tcp_v6_connect kretprobe",
			attach: func() (link.Link, error) {
				return link.Kretprobe(
					"tcp_v6_connect",
					objs.KretprobeTcpV6Connect,
					nil,
				)
			},
		},
		{
			name: "tcp_set_state kprobe",
			attach: func() (link.Link, error) {
				return link.Kprobe(
					"tcp_set_state",
					objs.KprobeTcpSetState,
					nil,
				)
			},
		},
	}

	links := make([]link.Link, 0, len(attachments))

	for _, attachment := range attachments {
		attachedLink, err := attachment.attach()
		if err != nil {
			closeTCPLifecycleLinks(links)
			return nil, fmt.Errorf("attaching %s: %w", attachment.name, err)
		}

		links = append(links, attachedLink)
	}

	return links, nil
}

func closeTCPLifecycleLinks(links []link.Link) {
	for index := len(links) - 1; index >= 0; index-- {
		if err := links[index].Close(); err != nil {
			log.Printf("closing TCP lifecycle probe: %s", err)
		}
	}
}

func readTCPLifecycleEvents(
	reader *ringbuf.Reader,
	output tcpLifecycleOutput,
	enricher *tcpLifecycleEnricher,
) {
	var record ringbuf.Record

	for {
		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}

			log.Printf("reading TCP lifecycle ring buffer: %s", err)
			return
		}

		payload, err := decodeTCPLifecycleEventPayload(
			record.RawSample,
			time.Now(),
		)
		if err != nil {
			log.Printf("processing TCP lifecycle event: %s", err)
			continue
		}

		payload = enricher.Enrich(payload)

		if err := output.WriteEvent(payload); err != nil {
			log.Printf("writing TCP lifecycle event: %s", err)
		}
	}
}

func reportTCPLifecycleDiagnostics(diagnostics *ebpf.Map) {
	labels := []struct {
		key  uint32
		name string
	}{
		{tcpLifecycleDiagnosticMapUpdateFailure, "map_update_failures"},
		{tcpLifecycleDiagnosticMissingCorrelation, "missing_correlation"},
		{tcpLifecycleDiagnosticUnsupportedObservation, "unsupported_observations"},
	}

	values := make(map[string]uint64, len(labels))

	for _, label := range labels {
		var perCPUCounts []uint64

		if err := diagnostics.Lookup(label.key, &perCPUCounts); err != nil {
			log.Printf(
				"reading TCP lifecycle diagnostic %s: %s",
				label.name,
				err,
			)
			continue
		}

		var total uint64
		for _, count := range perCPUCounts {
			total += count
		}

		values[label.name] = total
	}

	log.Printf(
		"TCP lifecycle diagnostic summary: map_update_failures=%d missing_correlation=%d unsupported_observations=%d",
		values["map_update_failures"],
		values["missing_correlation"],
		values["unsupported_observations"],
	)
}
