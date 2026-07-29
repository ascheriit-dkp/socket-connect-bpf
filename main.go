// Copyright 2019 Peter Stöckli
// Modified in 2026 by Ascheriit-Dkp.
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
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/p-/socket-connect-bpf/as"
	"github.com/p-/socket-connect-bpf/conv"
	"github.com/p-/socket-connect-bpf/linux"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-16 -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 bpf securitySocketConnectSrc.c -- -Iheaders/

var out output

var eventLosses struct {
	ipv4  atomic.Uint64
	ipv6  atomic.Uint64
	other atomic.Uint64
}

func main() {
	setupOutput()
	setupWorkers()
}

func setupOutput() {
	printAll := flag.Bool(
		"a",
		false,
		"include process arguments and ASN information",
	)

	outputFormat := flag.String(
		"output",
		outputFormatTable,
		"output format: table or ndjson",
	)

	flag.Parse()

	selectedOutput, err := newOutputForFormat(*outputFormat, *printAll)
	if err != nil {
		log.Fatal(err)
	}

	if *printAll {
		as.ParseASNumbersIPv4("./as/ip2asn-v4-u32.tsv")
		as.ParseASNumbersIPv6("./as/ip2asn-v6.tsv")
	}

	out = selectedOutput
}

func setupWorkers() {
	const fn = "security_socket_connect"

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.KprobeSecuritySocketConnect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	rd4, err := perf.NewReader(objs.Ipv4Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating IPv4 perf event reader: %s", err)
	}
	defer rd4.Close()

	rd6, err := perf.NewReader(objs.Ipv6Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating IPv6 perf event reader: %s", err)
	}
	defer rd6.Close()

	rdOther, err := perf.NewReader(
		objs.OtherSocketEvents,
		os.Getpagesize(),
	)
	if err != nil {
		log.Fatalf("creating other socket perf event reader: %s", err)
	}
	defer rdOther.Close()

	out.PrintHeader()

	var workers sync.WaitGroup
	workers.Add(3)

	go func() {
		defer workers.Done()

		for readIP4Events(rd4) {
		}
	}()

	go func() {
		defer workers.Done()

		for readIP6Events(rd6) {
		}
	}()

	go func() {
		defer workers.Done()

		for readOtherEvents(rdOther) {
		}
	}()

	<-stopper
	log.Println("received signal, exiting program")

	// Closing the readers interrupts blocked Read calls and allows all worker
	// goroutines to terminate cleanly.
	for _, reader := range []*perf.Reader{rd4, rd6, rdOther} {
		if err := reader.Close(); err != nil {
			log.Printf("closing perf event reader: %s", err)
		}
	}

	workers.Wait()
	reportEventLosses()
}

func readIP4Events(rd *perf.Reader) bool {
	var event IP4Event

	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}

		log.Printf("reading from IPv4 perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		eventLosses.ipv4.Add(record.LostSamples)

		log.Printf(
			"IPv4 perf event ring buffer full, dropped %d samples",
			record.LostSamples,
		)

		return true
	}

	if err := binary.Read(
		bytes.NewBuffer(record.RawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		log.Printf("parsing IPv4 perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	eventPayload.DestIP = conv.ToIP4(event.Daddr)
	eventPayload.DestPort = event.Dport

	asInfo := as.GetASInfoIPv4(eventPayload.DestIP)
	eventPayload.ASNameInfo = ASNameInfo{
		Name:     asInfo.Name,
		AsNumber: asInfo.AsNumber,
	}

	out.PrintLine(eventPayload)

	return true
}

func readIP6Events(rd *perf.Reader) bool {
	var event IP6Event

	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}

		log.Printf("reading from IPv6 perf event reader: %s", err)
		return true
	}

	if record.LostSamples != 0 {
		eventLosses.ipv6.Add(record.LostSamples)

		log.Printf(
			"IPv6 perf event ring buffer full, dropped %d samples",
			record.LostSamples,
		)

		return true
	}

	if err := binary.Read(
		bytes.NewBuffer(record.RawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		log.Printf("parsing IPv6 perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	eventPayload.DestIP = conv.ToIP6(event.Daddr1, event.Daddr2)
	eventPayload.DestPort = event.Dport

	asInfo := as.GetASInfoIPv6(eventPayload.DestIP)
	eventPayload.ASNameInfo = ASNameInfo{
		Name:     asInfo.Name,
		AsNumber: asInfo.AsNumber,
	}

	out.PrintLine(eventPayload)

	return true
}

func readOtherEvents(rd *perf.Reader) bool {
	var event OtherSocketEvent

	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return false
		}

		log.Printf(
			"reading from other socket perf event reader: %s",
			err,
		)

		return true
	}

	if record.LostSamples != 0 {
		eventLosses.other.Add(record.LostSamples)

		log.Printf(
			"other socket perf event ring buffer full, dropped %d samples",
			record.LostSamples,
		)

		return true
	}

	if err := binary.Read(
		bytes.NewBuffer(record.RawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		log.Printf("parsing other socket perf event: %s", err)
		return true
	}

	eventPayload := newGenericEventPayload(&event.Event)
	out.PrintLine(eventPayload)

	return true
}

func reportEventLosses() {
	ipv4Lost := eventLosses.ipv4.Load()
	ipv6Lost := eventLosses.ipv6.Load()
	otherLost := eventLosses.other.Load()
	totalLost := ipv4Lost + ipv6Lost + otherLost

	log.Printf(
		"perf event loss summary: total=%d ipv4=%d ipv6=%d other=%d",
		totalLost,
		ipv4Lost,
		ipv6Lost,
		otherLost,
	)
}

func newGenericEventPayload(event *Event) eventPayload {
	username := strconv.Itoa(int(event.UID))

	userInfo, err := user.LookupId(username)
	if err != nil {
		log.Printf("could not look up user with ID %d", event.UID)
	} else {
		username = userInfo.Username
	}

	pid := int(event.Pid)

	return eventPayload{
		KernelTime:    strconv.FormatUint(event.TsUs, 10),
		GoTime:        time.Now(),
		AddressFamily: conv.ToAddressFamily(int(event.Af)),
		Pid:           event.Pid,
		ProcessPath:   linux.ProcessPathForPid(pid),
		ProcessArgs:   linux.ProcessArgsForPid(pid),
		User:          username,
		Comm:          unix.ByteSliceToString(event.Task[:]),
	}
}

// Event contains fields common to every emitted socket event.
type Event struct {
	TsUs uint64
	Pid  uint32
	UID  uint32
	Af   uint16
	Task [16]byte
}

// IP4Event represents a socket connect attempt using AF_INET.
type IP4Event struct {
	Event
	Daddr uint32
	Dport uint16
}

// IP6Event represents a socket connect attempt using AF_INET6.
type IP6Event struct {
	Event
	Daddr1 uint64
	Daddr2 uint64
	Dport  uint16
}

// OtherSocketEvent represents socket connect attempts that do not use
// AF_INET, AF_INET6 or AF_UNIX.
type OtherSocketEvent struct {
	Event
}

type eventPayload struct {
	KernelTime    string
	GoTime        time.Time
	AddressFamily string
	Pid           uint32
	ProcessPath   string
	ProcessArgs   string
	User          string
	Comm           string
	Host           string
	DestIP         net.IP
	DestPort       uint16
	ASNameInfo     ASNameInfo
}

// ASNameInfo contains the name and number of an autonomous system.
type ASNameInfo struct {
	AsNumber uint32
	Name     string
}
