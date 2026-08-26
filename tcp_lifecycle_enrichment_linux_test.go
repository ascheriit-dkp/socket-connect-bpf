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

import "testing"

func TestTCPLifecycleEnricherBasicFields(t *testing.T) {
	processArgsCalls := 0
	asnCalls := 0

	enricher := newTCPLifecycleEnricherWithLookups(
		false,
		4,
		tcpLifecycleEnrichmentLookups{
			processPath: func(pid int) string {
				if pid != 1234 {
					t.Fatalf("unexpected PID: %d", pid)
				}
				return "/usr/bin/curl"
			},
			processArgs: func(int) string {
				processArgsCalls++
				return "--silent"
			},
			username: func(uid uint32) string {
				if uid != 1000 {
					t.Fatalf("unexpected UID: %d", uid)
				}
				return "alice"
			},
			asn: func(tcpLifecycleEventPayload) *tcpLifecycleASNPayload {
				asnCalls++
				return &tcpLifecycleASNPayload{Number: 64500}
			},
		},
	)

	payload := enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeConnectAttempt,
		ConnectionID: 1,
		PID:          1234,
		UID:          1000,
	})

	if payload.ProcessPath != "/usr/bin/curl" {
		t.Fatalf("unexpected process path: %q", payload.ProcessPath)
	}
	if payload.User != "alice" {
		t.Fatalf("unexpected user: %q", payload.User)
	}
	if payload.ProcessArgs != "" {
		t.Fatalf("unexpected process arguments: %q", payload.ProcessArgs)
	}
	if payload.ASN != nil {
		t.Fatalf("unexpected ASN enrichment: %#v", payload.ASN)
	}
	if processArgsCalls != 0 {
		t.Fatalf("process arguments lookup called %d times", processArgsCalls)
	}
	if asnCalls != 0 {
		t.Fatalf("ASN lookup called %d times", asnCalls)
	}
}

func TestTCPLifecycleEnricherCachesInitiatingMetadata(t *testing.T) {
	lookupCalls := 0

	enricher := newTCPLifecycleEnricherWithLookups(
		true,
		4,
		tcpLifecycleEnrichmentLookups{
			processPath: func(int) string {
				lookupCalls++
				return "/usr/bin/curl"
			},
			processArgs: func(int) string {
				return "--silent https://example.test"
			},
			username: func(uint32) string {
				return "alice"
			},
			asn: func(tcpLifecycleEventPayload) *tcpLifecycleASNPayload {
				return &tcpLifecycleASNPayload{
					Number: 64500,
					Name:   "Example Network",
				}
			},
		},
	)

	attempt := enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeConnectAttempt,
		ConnectionID: 42,
		PID:          1234,
		UID:          1000,
	})

	established := enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeEstablished,
		ConnectionID: 42,
		PID:          1234,
		UID:          1000,
	})

	closed := enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeClosed,
		ConnectionID: 42,
		PID:          1234,
		UID:          1000,
	})

	for name, payload := range map[string]tcpLifecycleEventPayload{
		"attempt":     attempt,
		"established": established,
		"closed":      closed,
	} {
		if payload.ProcessPath != "/usr/bin/curl" {
			t.Fatalf("%s: unexpected process path: %q", name, payload.ProcessPath)
		}
		if payload.ProcessArgs != "--silent https://example.test" {
			t.Fatalf("%s: unexpected process arguments: %q", name, payload.ProcessArgs)
		}
		if payload.User != "alice" {
			t.Fatalf("%s: unexpected user: %q", name, payload.User)
		}
		if payload.ASN == nil || payload.ASN.Number != 64500 {
			t.Fatalf("%s: unexpected ASN: %#v", name, payload.ASN)
		}
	}

	if lookupCalls != 1 {
		t.Fatalf("metadata lookup called %d times; want 1", lookupCalls)
	}
	if len(enricher.connections) != 0 {
		t.Fatalf("terminal event left %d cached connections", len(enricher.connections))
	}

	enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeConnectAttempt,
		ConnectionID: 42,
		PID:          1234,
		UID:          1000,
	})

	if lookupCalls != 2 {
		t.Fatalf("metadata lookup called %d times after cache removal; want 2", lookupCalls)
	}
}

func TestTCPLifecycleEnricherBoundsConnectionCache(t *testing.T) {
	lookupCalls := make(map[int]int)

	enricher := newTCPLifecycleEnricherWithLookups(
		false,
		1,
		tcpLifecycleEnrichmentLookups{
			processPath: func(pid int) string {
				lookupCalls[pid]++
				return "process"
			},
			processArgs: func(int) string { return "" },
			username:    func(uint32) string { return "user" },
			asn: func(tcpLifecycleEventPayload) *tcpLifecycleASNPayload {
				return nil
			},
		},
	)

	enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeConnectAttempt,
		ConnectionID: 1,
		PID:          1001,
	})
	enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeConnectAttempt,
		ConnectionID: 2,
		PID:          1002,
	})

	if len(enricher.connections) != 1 {
		t.Fatalf("cache contains %d entries; want 1", len(enricher.connections))
	}

	enricher.Enrich(tcpLifecycleEventPayload{
		EventType:    tcpLifecycleEventTypeEstablished,
		ConnectionID: 2,
		PID:          1002,
	})

	if lookupCalls[1001] != 1 {
		t.Fatalf("PID 1001 looked up %d times; want 1", lookupCalls[1001])
	}
	if lookupCalls[1002] != 2 {
		t.Fatalf("PID 1002 looked up %d times; want 2", lookupCalls[1002])
	}
	if len(enricher.connections) != 1 {
		t.Fatalf("cache grew to %d entries; want 1", len(enricher.connections))
	}
}
