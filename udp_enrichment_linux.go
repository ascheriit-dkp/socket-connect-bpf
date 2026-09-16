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

type udpEnricher struct {
	process *tcpLifecycleEnricher
}

func newUDPEnricher(
	includeExtendedFields bool,
	processes *processCache,
) *udpEnricher {
	return &udpEnricher{
		process: newTCPLifecycleEnricherWithProcessCache(
			includeExtendedFields,
			processes,
		),
	}
}

func (enricher *udpEnricher) Enrich(
	payload udpEventPayload,
) udpEventPayload {
	if enricher == nil || enricher.process == nil {
		return payload
	}

	lookupPayload := tcpLifecycleEventPayload{
		ObservedAt:        payload.ObservedAt,
		PID:               payload.PID,
		UID:               payload.UID,
		Comm:              payload.Comm,
		KernelTimestampNS: payload.KernelTimestampNS,
		Remote:            payload.Remote,
	}

	enrichment := enricher.process.lookup(lookupPayload)
	payload.ProcessPath = enrichment.ProcessPath
	payload.ProcessArgs = enrichment.ProcessArgs
	payload.User = enrichment.User
	payload.GID = cloneUint32Pointer(enrichment.GID)
	payload.ProcessStartTimeTicks = cloneUint64Pointer(
		enrichment.ProcessStartTimeTicks,
	)
	payload.Parent = cloneTCPLifecycleParent(enrichment.Parent)
	payload.Cgroup = cloneTCPLifecycleCgroup(enrichment.Cgroup)
	if payload.Cgroup == nil && payload.CgroupID != 0 {
		payload.Cgroup = &tcpLifecycleCgroupPayload{
			ID: uint64Pointer(payload.CgroupID),
		}
	}
	payload.Namespaces = cloneTCPLifecycleNamespaces(enrichment.Namespaces)
	payload.Container = cloneTCPLifecycleContainer(enrichment.Container)
	payload.ASN = cloneTCPLifecycleASN(enrichment.ASN)
	payload.DNS = cloneDNSCorrelation(enrichment.DNS)

	return payload
}
