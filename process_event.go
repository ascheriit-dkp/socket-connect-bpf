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
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	kernelProcessEventABIVersion uint16 = 1

	kernelProcessEventTypeExec uint8 = 1
	kernelProcessEventTypeExit uint8 = 2

	kernelProcessEventBinarySize = 56
)

type kernelProcessEvent struct {
	ABIVersion uint16
	EventType  uint8
	Reserved0  uint8
	TGID       uint32
	TID        uint32
	UID        uint32
	GID        uint32
	Reserved1  uint32

	KernelTimestampNS uint64
	CgroupID          uint64
	Task              [16]byte
}

type processEvent struct {
	EventType         uint8
	TGID              uint32
	TID               uint32
	UID               uint32
	GID               uint32
	KernelTimestampNS uint64
	CgroupID          uint64
	Comm              string
}

func decodeProcessEvent(rawSample []byte) (processEvent, error) {
	if len(rawSample) != kernelProcessEventBinarySize {
		return processEvent{}, fmt.Errorf(
			"unexpected process event size %d; want %d",
			len(rawSample),
			kernelProcessEventBinarySize,
		)
	}

	var event kernelProcessEvent
	if err := binary.Read(
		bytes.NewReader(rawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		return processEvent{}, fmt.Errorf("decode process event: %w", err)
	}

	if err := validateKernelProcessEvent(event); err != nil {
		return processEvent{}, err
	}

	return processEvent{
		EventType:         event.EventType,
		TGID:              event.TGID,
		TID:               event.TID,
		UID:               event.UID,
		GID:               event.GID,
		KernelTimestampNS: event.KernelTimestampNS,
		CgroupID:          event.CgroupID,
		Comm:              unix.ByteSliceToString(event.Task[:]),
	}, nil
}

func validateKernelProcessEvent(event kernelProcessEvent) error {
	if event.ABIVersion != kernelProcessEventABIVersion {
		return fmt.Errorf(
			"unsupported process event ABI version %d",
			event.ABIVersion,
		)
	}

	switch event.EventType {
	case kernelProcessEventTypeExec, kernelProcessEventTypeExit:
	default:
		return fmt.Errorf(
			"unsupported process event type %d",
			event.EventType,
		)
	}

	if event.TGID == 0 {
		return fmt.Errorf("process event has TGID zero")
	}
	if event.TID == 0 {
		return fmt.Errorf("process event has TID zero")
	}
	if event.KernelTimestampNS == 0 {
		return fmt.Errorf("process event has kernel timestamp zero")
	}
	if event.Reserved0 != 0 || event.Reserved1 != 0 {
		return fmt.Errorf("process event reserved fields are non-zero")
	}

	return nil
}
