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

type tcpLifecycleEnrichment struct {
	ProcessPath string
	ProcessArgs string
	User        string
	ASN         *tcpLifecycleASNPayload
}

type tcpLifecycleEnricher struct {
	includeExtendedFields bool
	connections           map[uint64]tcpLifecycleEnrichment
}

func newTCPLifecycleEnricher(
	includeExtendedFields bool,
) *tcpLifecycleEnricher {
	return &tcpLifecycleEnricher{
		includeExtendedFields: includeExtendedFields,
		connections:           make(map[uint64]tcpLifecycleEnrichment),
	}
}

func (enricher *tcpLifecycleEnricher) Enrich(
	payload tcpLifecycleEventPayload,
) tcpLifecycleEventPayload {
	enrichment, ok := enricher.connections[payload.ConnectionID]
	if !ok {
		enrichment = enricher.lookup(payload)
	}

	payload.ProcessPath = enrichment.ProcessPath
	payload.ProcessArgs = enrichment.ProcessArgs
	payload.User = enrichment.User
	payload.ASN = cloneTCPLifecycleASN(enrichment.ASN)

	switch payload.EventType {
	case tcpLifecycleEventTypeConnectFailed,
		tcpLifecycleEventTypeClosed:
		delete(enricher.connections, payload.ConnectionID)
	default:
		enricher.connections[payload.ConnectionID] = enrichment
	}

	return payload
}

func (enricher *tcpLifecycleEnricher) lookup(
	payload tcpLifecycleEventPayload,
) tcpLifecycleEnrichment {
	pid := int(payload.PID)
	enrichment := tcpLifecycleEnrichment{
		ProcessPath: linux.ProcessPathForPid(pid),
		User:        strconv.FormatUint(uint64(payload.UID), 10),
	}

	if userInfo, err := user.LookupId(enrichment.User); err == nil {
		enrichment.User = userInfo.Username
	}

	if !enricher.includeExtendedFields {
		return enrichment
	}

	enrichment.ProcessArgs = linux.ProcessArgsForPid(pid)
	enrichment.ASN = lookupTCPLifecycleASN(payload)

	return enrichment
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

func cloneTCPLifecycleASN(
	value *tcpLifecycleASNPayload,
) *tcpLifecycleASNPayload {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}
