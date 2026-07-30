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
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ascheriit-dkp/socket-connect-bpf/as"
	"github.com/ascheriit-dkp/socket-connect-bpf/conv"
	"github.com/ascheriit-dkp/socket-connect-bpf/linux"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-16 -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 bpf securitySocketConnectSrc.c -- -Iheaders/

var out output

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

	asnDirectory := flag.String(
		"asn-dir",
		"",
		"directory containing ASN datasets (default: as beside executable)",
	)

	flag.Parse()

	selectedOutput, err := newOutputForFormat(*outputFormat, *printAll)
	if err != nil {
		log.Fatal(err)
	}

	if *printAll {
		resolvedASNDirectory, resolveErr := resolveASNDirectory(*asnDirectory)
		if resolveErr != nil {
			log.Fatalf("resolving ASN data directory: %v", resolveErr)
		}

		if loadErr := loadASNData(resolvedASNDirectory); loadErr != nil {
			log.Fatalf(
				"loading ASN data from %q: %v",
				resolvedASNDirectory,
				loadErr,
			)
		}
	}

	out = selectedOutput
}

func resolveASNDirectory(configuredDirectory string) (string, error) {
	if configuredDirectory != "" {
		absoluteDirectory, err := filepath.Abs(configuredDirectory)
		if err != nil {
			return "", fmt.Errorf(
				"resolve configured directory %q: %w",
				configuredDirectory,
				err,
			)
		}

		return filepath.Clean(absoluteDirectory), nil
	}

	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine executable path: %w", err)
	}

	resolvedExecutablePath, err := filepath.EvalSymlinks(executablePath)
	if err != nil {
		return "", fmt.Errorf(
			"resolve executable path %q: %w",
			executablePath,
			err,
		)
	}

	return filepath.Join(
		filepath.Dir(resolvedExecutablePath),
		"as",
	), nil
}

func loadASNData(asnDirectory string) error {
	ipv4Path := filepath.Join(
		asnDirectory,
		"ip2asn-v4-u32.tsv",
	)

	if err := as.ParseASNumbersIPv4(ipv4Path); err != nil {
		return fmt.Errorf("load IPv4 ASN dataset: %w", err)
	}

	ipv6Path := filepath.Join(
		asnDirectory,
		"ip2asn-v6.tsv",
	)

	if err := as.ParseASNumbersIPv6(ipv6Path); err != nil {
		return fmt.Errorf("load IPv6 ASN dataset: %w", err)
	}

	return nil
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

	reader, err := ringbuf.NewReader(objs.SocketEvents)
	if err != nil {
		log.Fatalf("creating socket event ring-buffer reader: %s", err)
	}

	out.PrintHeader()

	go func() {
		<-stopper

		log.Println("received signal, exiting program")

		closeRingBufferReader(reader)
	}()

	readSocketEvents(reader)

	closeRingBufferReader(reader)

	// Stop producing events before reading the loss counter. Otherwise,
	// connections observed after the reader closes could be counted as drops
	// caused only by shutdown.
	if err := kp.Close(); err != nil {
		log.Printf("closing security_socket_connect kprobe: %s", err)
	}

	reportDroppedEvents(objs.DroppedEvents)
}

func closeRingBufferReader(reader *ringbuf.Reader) {
	if err := reader.Close(); err != nil &&
		!errors.Is(err, os.ErrClosed) {
		log.Printf(
			"closing socket event ring-buffer reader: %s",
			err,
		)
	}
}

func readSocketEvents(reader *ringbuf.Reader) {
	var record ringbuf.Record

	for {
		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}

			log.Printf(
				"reading from socket event ring buffer: %s",
				err,
			)

			return
		}

		if err := processSocketEventRecord(record.RawSample); err != nil {
			log.Printf("processing socket event: %s", err)
		}
	}
}

func processSocketEventRecord(rawSample []byte) error {
	if len(rawSample) != kernelSocketEventBinarySize {
		return fmt.Errorf(
			"unexpected record size %d; want %d",
			len(rawSample),
			kernelSocketEventBinarySize,
		)
	}

	var event kernelSocketEvent

	if err := binary.Read(
		bytes.NewReader(rawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		return fmt.Errorf("decode kernel event: %w", err)
	}

	if err := validateKernelSocketEvent(event); err != nil {
		return err
	}

	out.PrintLine(newKernelEventPayload(event))

	return nil
}

func validateKernelSocketEvent(event kernelSocketEvent) error {
	if event.ABIVersion != kernelEventABIVersion {
		return fmt.Errorf(
			"unsupported kernel event ABI version %d",
			event.ABIVersion,
		)
	}

	if event.EventType != kernelEventTypeConnectAttempt {
		return fmt.Errorf(
			"unsupported kernel event type %d",
			event.EventType,
		)
	}

	switch event.AddressLength {
	case kernelAddressLengthNone:
		if event.AddressFamily == unix.AF_INET ||
			event.AddressFamily == unix.AF_INET6 {
			return fmt.Errorf(
				"address family %d has no destination address",
				event.AddressFamily,
			)
		}

	case kernelAddressLengthIPv4:
		if event.AddressFamily != unix.AF_INET {
			return fmt.Errorf(
				"IPv4 address length used with address family %d",
				event.AddressFamily,
			)
		}

	case kernelAddressLengthIPv6:
		if event.AddressFamily != unix.AF_INET6 {
			return fmt.Errorf(
				"IPv6 address length used with address family %d",
				event.AddressFamily,
			)
		}

	default:
		return fmt.Errorf(
			"unsupported destination address length %d",
			event.AddressLength,
		)
	}

	return nil
}

func reportDroppedEvents(droppedEvents *ebpf.Map) {
	const counterKey uint32 = 0

	var perCPUCounts []uint64

	if err := droppedEvents.Lookup(
		counterKey,
		&perCPUCounts,
	); err != nil {
		log.Printf(
			"reading ring-buffer event loss counter: %s",
			err,
		)

		return
	}

	var total uint64

	for _, count := range perCPUCounts {
		total += count
	}

	log.Printf(
		"ring-buffer event loss summary: total=%d",
		total,
	)
}

func newKernelEventPayload(event kernelSocketEvent) eventPayload {
	username := strconv.Itoa(int(event.UID))

	userInfo, err := user.LookupId(username)
	if err != nil {
		log.Printf("could not look up user with ID %d", event.UID)
	} else {
		username = userInfo.Username
	}

	pid := int(event.PID)

	payload := eventPayload{
		KernelTime: strconv.FormatUint(
			event.KernelTimestampNS,
			10,
		),
		GoTime:        time.Now(),
		AddressFamily: conv.ToAddressFamily(int(event.AddressFamily)),
		Pid:           event.PID,
		ProcessPath:   linux.ProcessPathForPid(pid),
		ProcessArgs:   linux.ProcessArgsForPid(pid),
		User:          username,
		Comm:           unix.ByteSliceToString(event.Task[:]),
		DestIP:         event.destinationIP(),
		DestPort:       event.DestinationPort,
	}

	switch event.AddressLength {
	case kernelAddressLengthIPv4:
		asInfo := as.GetASInfoIPv4(payload.DestIP)

		payload.ASNameInfo = ASNameInfo{
			Name:     asInfo.Name,
			AsNumber: asInfo.AsNumber,
		}

	case kernelAddressLengthIPv6:
		asInfo := as.GetASInfoIPv6(payload.DestIP)

		payload.ASNameInfo = ASNameInfo{
			Name:     asInfo.Name,
			AsNumber: asInfo.AsNumber,
		}
	}

	return payload
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
