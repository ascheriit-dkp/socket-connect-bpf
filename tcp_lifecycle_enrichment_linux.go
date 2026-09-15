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
	"os/user"
	"strconv"

	"github.com/ascheriit-dkp/socket-connect-bpf/as"
	"github.com/ascheriit-dkp/socket-connect-bpf/linux"
)

const maxTCPLifecycleEnrichmentEntries = 65536

type tcpLifecycleEnrichment struct {
	ProcessPath           string
	ProcessArgs           string
	User                  string
	GID                   *uint32
	ProcessStartTimeTicks *uint64
	Parent                *tcpLifecycleProcessParentPayload
	Cgroup                *tcpLifecycleCgroupPayload
	Namespaces            *tcpLifecycleNamespacesPayload
	Container             *tcpLifecycleContainerPayload
	ASN                   *tcpLifecycleASNPayload
}

type tcpLifecycleEnrichmentLookups struct {
	processPath func(int) string
	processArgs func(int) string
	username    func(uint32) string
	context     func(int) processContextSnapshot
	asn         func(tcpLifecycleEventPayload) *tcpLifecycleASNPayload
}

type tcpLifecycleEnricher struct {
	includeExtendedFields bool
	maxEntries            int
	connections           map[uint64]tcpLifecycleEnrichment
	lookups               tcpLifecycleEnrichmentLookups
	processes             *processCache
}

func newTCPLifecycleEnricher(
	includeExtendedFields bool,
) *tcpLifecycleEnricher {
	return newTCPLifecycleEnricherWithProcessCache(
		includeExtendedFields,
		nil,
	)
}

func newTCPLifecycleEnricherWithProcessCache(
	includeExtendedFields bool,
	processes *processCache,
) *tcpLifecycleEnricher {
	enricher := newTCPLifecycleEnricherWithLookups(
		includeExtendedFields,
		maxTCPLifecycleEnrichmentEntries,
		defaultTCPLifecycleEnrichmentLookups(),
	)
	enricher.processes = processes

	return enricher
}

func newTCPLifecycleEnricherWithLookups(
	includeExtendedFields bool,
	maxEntries int,
	lookups tcpLifecycleEnrichmentLookups,
) *tcpLifecycleEnricher {
	if maxEntries < 0 {
		maxEntries = 0
	}

	return &tcpLifecycleEnricher{
		includeExtendedFields: includeExtendedFields,
		maxEntries:            maxEntries,
		connections:           make(map[uint64]tcpLifecycleEnrichment),
		lookups:               lookups,
	}
}

func defaultTCPLifecycleEnrichmentLookups() tcpLifecycleEnrichmentLookups {
	return tcpLifecycleEnrichmentLookups{
		processPath: linux.ProcessPathForPid,
		processArgs: linux.ProcessArgsForPid,
		username:    lookupTCPLifecycleUsername,
		context:     lookupProcessContext,
		asn:         lookupTCPLifecycleASN,
	}
}

func (enricher *tcpLifecycleEnricher) Enrich(
	payload tcpLifecycleEventPayload,
) tcpLifecycleEventPayload {
	enrichment, cached := enricher.connections[payload.ConnectionID]
	if !cached {
		enrichment = enricher.lookup(payload)
	}

	payload.ProcessPath = enrichment.ProcessPath
	payload.ProcessArgs = enrichment.ProcessArgs
	payload.User = enrichment.User
	payload.GID = cloneUint32Pointer(enrichment.GID)
	payload.ProcessStartTimeTicks = cloneUint64Pointer(
		enrichment.ProcessStartTimeTicks,
	)
	payload.Parent = cloneTCPLifecycleParent(enrichment.Parent)
	payload.Cgroup = cloneTCPLifecycleCgroup(enrichment.Cgroup)
	payload.Namespaces = cloneTCPLifecycleNamespaces(enrichment.Namespaces)
	payload.Container = cloneTCPLifecycleContainer(enrichment.Container)
	payload.ASN = cloneTCPLifecycleASN(enrichment.ASN)

	switch payload.EventType {
	case tcpLifecycleEventTypeConnectFailed,
		tcpLifecycleEventTypeClosed:
		delete(enricher.connections, payload.ConnectionID)
	default:
		if cached || len(enricher.connections) < enricher.maxEntries {
			enricher.connections[payload.ConnectionID] = enrichment
		}
	}

	return payload
}

func (enricher *tcpLifecycleEnricher) lookup(
	payload tcpLifecycleEventPayload,
) tcpLifecycleEnrichment {
	pid := int(payload.PID)
	enrichment := tcpLifecycleEnrichment{}
	trackedProcess := false

	if enricher.processes != nil {
		snapshot, found, tracked := enricher.processes.Lookup(
			payload.PID,
			payload.UID,
			payload.Comm,
			payload.KernelTimestampNS,
		)
		trackedProcess = tracked
		if found {
			enrichment.ProcessPath = snapshot.Executable
			enrichment.User = snapshot.User
			enrichment.GID = uint32Pointer(snapshot.GID)
			applyProcessContext(
				&enrichment,
				snapshot.Context,
				uint64PointerIfNonZero(snapshot.CgroupID),
			)
			if enricher.includeExtendedFields {
				enrichment.ProcessArgs = snapshot.Arguments
			}
		}
	}

	if !trackedProcess {
		if enrichment.ProcessPath == "" {
			enrichment.ProcessPath = enricher.lookups.processPath(pid)
		}

		if enricher.lookups.context != nil {
			context := enricher.lookups.context(pid)
			if enrichment.GID == nil {
				enrichment.GID = cloneUint32Pointer(context.GID)
			}
			applyProcessContext(&enrichment, context, nil)
		}
	}

	if enrichment.User == "" {
		enrichment.User = enricher.lookups.username(payload.UID)
	}

	if !enricher.includeExtendedFields {
		return enrichment
	}

	if enrichment.ProcessArgs == "" && !trackedProcess {
		enrichment.ProcessArgs = enricher.lookups.processArgs(pid)
	}
	enrichment.ASN = enricher.lookups.asn(payload)

	return enrichment
}

func applyProcessContext(
	enrichment *tcpLifecycleEnrichment,
	context processContextSnapshot,
	cgroupID *uint64,
) {
	if context.StartTimeTicks != 0 {
		enrichment.ProcessStartTimeTicks = uint64Pointer(context.StartTimeTicks)
	}

	if context.ParentPID != 0 {
		parent := &tcpLifecycleProcessParentPayload{
			PID: context.ParentPID,
		}
		if context.ParentStartTimeTicks != 0 {
			parent.StartTimeTicks = uint64Pointer(context.ParentStartTimeTicks)
		}
		enrichment.Parent = parent
	}

	if cgroupID != nil || context.CgroupPath != "" {
		enrichment.Cgroup = &tcpLifecycleCgroupPayload{
			ID:   cloneUint64Pointer(cgroupID),
			Path: context.CgroupPath,
		}
	}

	if !processNamespacesEmpty(context.Namespaces) {
		enrichment.Namespaces = &tcpLifecycleNamespacesPayload{
			Cgroup: context.Namespaces.Cgroup,
			IPC:    context.Namespaces.IPC,
			Mount:  context.Namespaces.Mount,
			Net:    context.Namespaces.Net,
			PID:    context.Namespaces.PID,
			User:   context.Namespaces.User,
			UTS:    context.Namespaces.UTS,
		}
	}

	if context.Container != nil {
		enrichment.Container = &tcpLifecycleContainerPayload{
			Runtime: context.Container.Runtime,
			ID:      context.Container.ID,
		}
	}
}

func uint64PointerIfNonZero(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return uint64Pointer(value)
}

func lookupTCPLifecycleUsername(uid uint32) string {
	uidText := strconv.FormatUint(uint64(uid), 10)

	if userInfo, err := user.LookupId(uidText); err == nil {
		return userInfo.Username
	}

	return uidText
}

func lookupTCPLifecycleASN(
	payload tcpLifecycleEventPayload,
) *tcpLifecycleASNPayload {
	if payload.Remote.IP == nil {
		return nil
	}

	if payload.Remote.IP.To4() != nil {
		info := as.GetASInfoIPv4(payload.Remote.IP)
		if info.AsNumber == 0 {
			return nil
		}

		return &tcpLifecycleASNPayload{
			Number: info.AsNumber,
			Name:   info.Name,
		}
	}

	if payload.Remote.IP.To16() != nil {
		info := as.GetASInfoIPv6(payload.Remote.IP)
		if info.AsNumber == 0 {
			return nil
		}

		return &tcpLifecycleASNPayload{
			Number: info.AsNumber,
			Name:   info.Name,
		}
	}

	return nil
}

func cloneTCPLifecycleParent(
	value *tcpLifecycleProcessParentPayload,
) *tcpLifecycleProcessParentPayload {
	if value == nil {
		return nil
	}

	return &tcpLifecycleProcessParentPayload{
		PID:            value.PID,
		StartTimeTicks: cloneUint64Pointer(value.StartTimeTicks),
	}
}

func cloneTCPLifecycleCgroup(
	value *tcpLifecycleCgroupPayload,
) *tcpLifecycleCgroupPayload {
	if value == nil {
		return nil
	}

	return &tcpLifecycleCgroupPayload{
		ID:   cloneUint64Pointer(value.ID),
		Path: value.Path,
	}
}

func cloneTCPLifecycleNamespaces(
	value *tcpLifecycleNamespacesPayload,
) *tcpLifecycleNamespacesPayload {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}

func cloneTCPLifecycleContainer(
	value *tcpLifecycleContainerPayload,
) *tcpLifecycleContainerPayload {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}

func cloneTCPLifecycleASN(
	value *tcpLifecycleASNPayload,
) *tcpLifecycleASNPayload {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}

func cloneUint32Pointer(value *uint32) *uint32 {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}
