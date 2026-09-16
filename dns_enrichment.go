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
	"container/list"
	"context"
	"flag"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	dnsCorrelationSourceReverseDNS = "reverse_dns"
	dnsCorrelationConfidenceLow    = "low"

	defaultDNSCacheEntries = 4096
	defaultDNSTimeout      = 250 * time.Millisecond
	defaultDNSPositiveTTL  = 10 * time.Minute
	defaultDNSNegativeTTL  = time.Minute
)

var dnsEnrichmentFlag = flag.Bool(
	"dns",
	false,
	"add low-confidence reverse DNS enrichment to TCP lifecycle or UDP events",
)

type dnsCorrelationPayload struct {
	Name       string
	Source     string
	Confidence string
}

type dnsResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
}

type dnsCacheEntry struct {
	key       string
	value     *dnsCorrelationPayload
	expiresAt time.Time
}

type dnsCorrelator struct {
	mu          sync.Mutex
	maxEntries  int
	timeout     time.Duration
	positiveTTL time.Duration
	negativeTTL time.Duration
	resolver    dnsResolver
	now         func() time.Time
	entries     map[string]*list.Element
	lru         list.List
}

var defaultDNSCorrelator = newDNSCorrelator(
	defaultDNSCacheEntries,
	defaultDNSTimeout,
	defaultDNSPositiveTTL,
	defaultDNSNegativeTTL,
	net.DefaultResolver,
	time.Now,
)

func dnsEnrichmentEnabled() bool {
	return dnsEnrichmentFlag != nil && *dnsEnrichmentFlag
}

func newDNSCorrelator(
	maxEntries int,
	timeout time.Duration,
	positiveTTL time.Duration,
	negativeTTL time.Duration,
	resolver dnsResolver,
	now func() time.Time,
) *dnsCorrelator {
	if maxEntries < 0 {
		maxEntries = 0
	}
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}
	if positiveTTL <= 0 {
		positiveTTL = defaultDNSPositiveTTL
	}
	if negativeTTL <= 0 {
		negativeTTL = defaultDNSNegativeTTL
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if now == nil {
		now = time.Now
	}

	return &dnsCorrelator{
		maxEntries:  maxEntries,
		timeout:     timeout,
		positiveTTL: positiveTTL,
		negativeTTL: negativeTTL,
		resolver:    resolver,
		now:         now,
		entries:     make(map[string]*list.Element),
	}
}

func (correlator *dnsCorrelator) Lookup(ip net.IP) *dnsCorrelationPayload {
	if correlator == nil || ip == nil {
		return nil
	}

	key := ip.String()
	if key == "<nil>" || key == "" {
		return nil
	}

	now := correlator.now()
	if value, ok := correlator.cached(key, now); ok {
		return value
	}

	ctx, cancel := context.WithTimeout(context.Background(), correlator.timeout)
	defer cancel()

	names, err := correlator.resolver.LookupAddr(ctx, key)
	value := normalizeDNSCorrelation(names, err)

	ttl := correlator.negativeTTL
	if value != nil {
		ttl = correlator.positiveTTL
	}
	correlator.store(key, value, now.Add(ttl))

	return cloneDNSCorrelation(value)
}

func (correlator *dnsCorrelator) cached(
	key string,
	now time.Time,
) (*dnsCorrelationPayload, bool) {
	correlator.mu.Lock()
	defer correlator.mu.Unlock()

	element, ok := correlator.entries[key]
	if !ok {
		return nil, false
	}

	entry := element.Value.(*dnsCacheEntry)
	if !now.Before(entry.expiresAt) {
		delete(correlator.entries, key)
		correlator.lru.Remove(element)
		return nil, false
	}

	correlator.lru.MoveToBack(element)
	return cloneDNSCorrelation(entry.value), true
}

func (correlator *dnsCorrelator) store(
	key string,
	value *dnsCorrelationPayload,
	expiresAt time.Time,
) {
	if correlator.maxEntries == 0 {
		return
	}

	correlator.mu.Lock()
	defer correlator.mu.Unlock()

	if element, ok := correlator.entries[key]; ok {
		entry := element.Value.(*dnsCacheEntry)
		entry.value = cloneDNSCorrelation(value)
		entry.expiresAt = expiresAt
		correlator.lru.MoveToBack(element)
		return
	}

	element := correlator.lru.PushBack(&dnsCacheEntry{
		key:       key,
		value:     cloneDNSCorrelation(value),
		expiresAt: expiresAt,
	})
	correlator.entries[key] = element

	for len(correlator.entries) > correlator.maxEntries {
		oldest := correlator.lru.Front()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*dnsCacheEntry)
		delete(correlator.entries, entry.key)
		correlator.lru.Remove(oldest)
	}
}

func normalizeDNSCorrelation(
	names []string,
	lookupErr error,
) *dnsCorrelationPayload {
	if lookupErr != nil {
		return nil
	}

	for _, name := range names {
		normalized := strings.ToLower(strings.TrimSpace(name))
		normalized = strings.TrimSuffix(normalized, ".")
		if normalized == "" {
			continue
		}

		return &dnsCorrelationPayload{
			Name:       normalized,
			Source:     dnsCorrelationSourceReverseDNS,
			Confidence: dnsCorrelationConfidenceLow,
		}
	}

	return nil
}

func lookupDNSCorrelation(ip net.IP) *dnsCorrelationPayload {
	if !dnsEnrichmentEnabled() {
		return nil
	}
	return defaultDNSCorrelator.Lookup(ip)
}

func cloneDNSCorrelation(
	value *dnsCorrelationPayload,
) *dnsCorrelationPayload {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func formatDNSCorrelation(value *dnsCorrelationPayload) string {
	if value == nil || value.Name == "" {
		return ""
	}
	return value.Name + " [" + value.Source + "/" + value.Confidence + "]"
}
