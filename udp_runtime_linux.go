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

func setupUDPWorkers(filters kernelFilterOptions) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	udpObjs := udpObjects{}
	if err := loadUdpObjects(&udpObjs, nil); err != nil {
		log.Fatalf("loading UDP objects: %v", err)
	}
	defer udpObjs.Close()

	if err := configureKernelFilters(
		filters,
		kernelFilterMaps{
			config: udpObjs.UdpFilterConfig,
			pids:   udpObjs.UdpPidFilters,
			uids:   udpObjs.UdpUidFilters,
			ports:  udpObjs.UdpPortFilters,
		},
	); err != nil {
		log.Fatalf("configuring UDP kernel filters: %v", err)
	}

	udpLinks, err := attachUDPPrograms(&udpObjs)
	if err != nil {
		log.Fatal(err)
	}

	processObjs := bpfObjects{}
	if err := loadBpfObjects(&processObjs, nil); err != nil {
		closeUDPLinks(udpLinks)
		log.Fatalf("loading process attribution objects: %v", err)
	}
	defer processObjs.Close()

	processLinks, err := attachProcessAttributionPrograms(&processObjs)
	if err != nil {
		closeUDPLinks(udpLinks)
		log.Fatal(err)
	}

	udpReader, err := ringbuf.NewReader(udpObjs.UdpEvents)
	if err != nil {
		closeUDPLinks(processLinks)
		closeUDPLinks(udpLinks)
		log.Fatalf("creating UDP ring-buffer reader: %v", err)
	}

	processReader, err := ringbuf.NewReader(processObjs.ProcessEvents)
	if err != nil {
		closeRingBufferReader(udpReader)
		closeUDPLinks(processLinks)
		closeUDPLinks(udpLinks)
		log.Fatalf("creating UDP process ring-buffer reader: %v", err)
	}

	output, err := newUDPOutputForFormat(selectedOutputFormat(), os.Stdout)
	if err != nil {
		closeRingBufferReader(processReader)
		closeRingBufferReader(udpReader)
		closeUDPLinks(processLinks)
		closeUDPLinks(udpLinks)
		log.Fatal(err)
	}
	if err := output.PrintHeader(); err != nil {
		closeRingBufferReader(processReader)
		closeRingBufferReader(udpReader)
		closeUDPLinks(processLinks)
		closeUDPLinks(udpLinks)
		log.Fatal(err)
	}

	processes := newProcessCache(selectedExtendedOutput())
	enricher := newUDPEnricher(selectedExtendedOutput(), processes)

	processReaderDone := make(chan struct{})
	go func() {
		defer close(processReaderDone)
		readProcessEvents(processReader, processes)
	}()

	go func() {
		<-stopper
		log.Println("received signal, exiting program")
		closeRingBufferReader(udpReader)
		closeRingBufferReader(processReader)
	}()

	readUDPEvents(udpReader, output, enricher)
	closeRingBufferReader(udpReader)
	closeRingBufferReader(processReader)
	<-processReaderDone
	closeUDPLinks(processLinks)
	closeUDPLinks(udpLinks)

	reportUDPDroppedEvents(udpObjs.UdpDroppedEvents)
	reportProcessDroppedEvents(processObjs.ProcessDroppedEvents)
}

func attachUDPPrograms(objs *udpObjects) ([]link.Link, error) {
	attachments := []struct {
		name   string
		attach func() (link.Link, error)
	}{
		{
			name: "udp_sendmsg kprobe",
			attach: func() (link.Link, error) {
				return link.Kprobe("udp_sendmsg", objs.KprobeUdpSendmsg, nil)
			},
		},
		{
			name: "udpv6_sendmsg kprobe",
			attach: func() (link.Link, error) {
				return link.Kprobe("udpv6_sendmsg", objs.KprobeUdpv6Sendmsg, nil)
			},
		},
	}

	links := make([]link.Link, 0, len(attachments))
	for _, attachment := range attachments {
		attached, err := attachment.attach()
		if err != nil {
			closeUDPLinks(links)
			return nil, fmt.Errorf("attaching %s: %w", attachment.name, err)
		}
		links = append(links, attached)
	}
	return links, nil
}

func attachProcessAttributionPrograms(objs *bpfObjects) ([]link.Link, error) {
	attachments := []struct {
		name    string
		program *ebpf.Program
	}{
		{
			name:    "sched_process_exec",
			program: objs.RawTracepointSchedProcessExec,
		},
		{
			name:    "sched_process_exit",
			program: objs.RawTracepointSchedProcessExit,
		},
	}

	links := make([]link.Link, 0, len(attachments))
	for _, attachment := range attachments {
		attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    attachment.name,
			Program: attachment.program,
		})
		if err != nil {
			closeUDPLinks(links)
			return nil, fmt.Errorf(
				"attaching %s raw tracepoint: %w",
				attachment.name,
				err,
			)
		}
		links = append(links, attached)
	}
	return links, nil
}

func closeUDPLinks(links []link.Link) {
	for index := len(links) - 1; index >= 0; index-- {
		if err := links[index].Close(); err != nil {
			log.Printf("closing UDP probe: %v", err)
		}
	}
}

func readUDPEvents(
	reader *ringbuf.Reader,
	output udpOutput,
	enricher *udpEnricher,
) {
	var record ringbuf.Record
	for {
		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("reading UDP ring buffer: %v", err)
			return
		}

		payload, err := decodeUDPEventPayload(record.RawSample, time.Now())
		if err != nil {
			log.Printf("processing UDP event: %v", err)
			continue
		}
		payload = enricher.Enrich(payload)
		if err := output.WriteEvent(payload); err != nil {
			log.Printf("writing UDP event: %v", err)
		}
	}
}

func reportUDPDroppedEvents(droppedEvents *ebpf.Map) {
	const counterKey uint32 = 0
	var perCPUCounts []uint64
	if err := droppedEvents.Lookup(counterKey, &perCPUCounts); err != nil {
		log.Printf("reading UDP event loss counter: %v", err)
		return
	}

	var total uint64
	for _, count := range perCPUCounts {
		total += count
	}
	log.Printf("UDP event loss summary: total=%d", total)
}
