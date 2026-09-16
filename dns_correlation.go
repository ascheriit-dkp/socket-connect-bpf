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
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxDNSCorrelationEntries  = 65536
	maxDNSObservationLineSize = 64 * 1024

	dnsConfidenceHigh   = "high"
	dnsConfidenceMedium = "medium"

	defaultDNSObservationSource = "dns_observation_file"
)

type dnsCorrelationPayload struct {
	Name       string
	Source     string
	Confidence string
	ObservedAt time.Time
	ExpiresAt  time.Time
}

type dnsObservation struct {
	IP         string
	Name       string
	Source     string
	ObservedAt time.Time
	ExpiresAt  time.Time
	PID        *uint32
}

type dnsObservationRecord struct {
	IP         string  `json:"ip"`
	Name       string  `json:"name"`
	ObservedAt string  `json:"observed_at"`
	TTLSeconds uint32  `json:"ttl_seconds"`
	PID        *uint32 `json:"pid,omitempty"`
	Source     string  `json:"source,omitempty"`
}

type dnsCorrelator struct {
	mu      sync.RWMutex
	entries map[string][]dnsObservation
	count   int
}

var activeDNSCorrelator = newDNSCorrelator()
var registeredDNSObservationFiles = registerDNSCorrelationFlags(flag.CommandLine)

type dnsObservationFileValues []string

func (values *dnsObservationFileValues) String() string {
	if values == nil {
		return ""
	}

	return strings.Join(*values, ",")
}

func (values *dnsObservationFileValues) Set(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("--dns-observations path must not be empty")
	}

	observations, err := loadDNSObservations(path)
	if err != nil {
		return err
	}
	if err := activeDNSCorrelator.Add(observations); err != nil {
		return err
	}

	*values = append(*values, path)
	return nil
}

func registerDNSCorrelationFlags(
	flagSet *flag.FlagSet,
) *dnsObservationFileValues {
	values := &dnsObservationFileValues{}
	flagSet.Var(
		values,
		"dns-observations",
		"load DNS observation JSONL for optional IP-to-name correlation; may be repeated",
	)

	return values
}

func newDNSCorrelator() *dnsCorrelator {
	return &dnsCorrelator{
		entries: make(map[string][]dnsObservation),
	}
}

func loadDNSObservations(path string) ([]dnsObservation, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open DNS observations %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxDNSObservationLineSize)

	observations := make([]dnsObservation, 0)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var record dnsObservationRecord
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf(
				"parse DNS observations %q line %d: %w",
				path,
				lineNumber,
				err,
			)
		}

		var trailing interface{}
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				err = fmt.Errorf("multiple JSON values")
			}
			return nil, fmt.Errorf(
				"parse DNS observations %q line %d: trailing data: %w",
				path,
				lineNumber,
				err,
			)
		}

		observation, err := newDNSObservation(record)
		if err != nil {
			return nil, fmt.Errorf(
				"parse DNS observations %q line %d: %w",
				path,
				lineNumber,
				err,
			)
		}
		observations = append(observations, observation)
		if len(observations) > maxDNSCorrelationEntries {
			return nil, fmt.Errorf(
				"DNS observations %q exceed maximum of %d records",
				path,
				maxDNSCorrelationEntries,
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read DNS observations %q: %w", path, err)
	}

	return observations, nil
}

func newDNSObservation(record dnsObservationRecord) (dnsObservation, error) {
	ip := net.ParseIP(strings.TrimSpace(record.IP))
	if ip == nil {
		return dnsObservation{}, fmt.Errorf("invalid IP %q", record.IP)
	}

	name := strings.TrimSpace(record.Name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return dnsObservation{}, fmt.Errorf("DNS name must not be empty")
	}
	if len(name) > 253 {
		return dnsObservation{}, fmt.Errorf("DNS name exceeds 253 bytes")
	}

	observedAt, err := time.Parse(
		time.RFC3339Nano,
		strings.TrimSpace(record.ObservedAt),
	)
	if err != nil {
		return dnsObservation{}, fmt.Errorf(
			"invalid observed_at %q: %w",
			record.ObservedAt,
			err,
		)
	}
	if record.TTLSeconds == 0 {
		return dnsObservation{}, fmt.Errorf("ttl_seconds must be greater than zero")
	}

	source := strings.TrimSpace(record.Source)
	if source == "" {
		source = defaultDNSObservationSource
	}
	if len(source) > 64 {
		return dnsObservation{}, fmt.Errorf("DNS source exceeds 64 bytes")
	}

	var pid *uint32
	if record.PID != nil {
		copiedPID := *record.PID
		pid = &copiedPID
	}

	return dnsObservation{
		IP:         ip.String(),
		Name:       name,
		Source:     source,
		ObservedAt: observedAt,
		ExpiresAt: observedAt.Add(
			time.Duration(record.TTLSeconds) * time.Second,
		),
		PID: pid,
	}, nil
}

func (correlator *dnsCorrelator) Add(observations []dnsObservation) error {
	if correlator == nil || len(observations) == 0 {
		return nil
	}

	correlator.mu.Lock()
	defer correlator.mu.Unlock()

	if correlator.count+len(observations) > maxDNSCorrelationEntries {
		return fmt.Errorf(
			"DNS correlation cache would exceed maximum of %d records",
			maxDNSCorrelationEntries,
		)
	}

	for _, observation := range observations {
		correlator.entries[observation.IP] = append(
			correlator.entries[observation.IP],
			observation,
		)
		correlator.count++
	}

	return nil
}

func (correlator *dnsCorrelator) Lookup(
	ip net.IP,
	pid uint32,
	observedAt time.Time,
) *dnsCorrelationPayload {
	if correlator == nil || ip == nil || observedAt.IsZero() {
		return nil
	}

	correlator.mu.RLock()
	candidates := correlator.entries[ip.String()]
	correlator.mu.RUnlock()
	if len(candidates) == 0 {
		return nil
	}

	var best *dnsObservation
	bestConfidence := ""
	for index := range candidates {
		candidate := &candidates[index]
		if observedAt.Before(candidate.ObservedAt) ||
			observedAt.After(candidate.ExpiresAt) {
			continue
		}

		confidence := dnsConfidenceMedium
		if candidate.PID != nil {
			if *candidate.PID != pid {
				continue
			}
			confidence = dnsConfidenceHigh
		}

		if best == nil ||
			confidenceRank(confidence) > confidenceRank(bestConfidence) ||
			(confidence == bestConfidence &&
				candidate.ObservedAt.After(best.ObservedAt)) {
			best = candidate
			bestConfidence = confidence
		}
	}

	if best == nil {
		return nil
	}

	return &dnsCorrelationPayload{
		Name:       best.Name,
		Source:     best.Source,
		Confidence: bestConfidence,
		ObservedAt: best.ObservedAt,
		ExpiresAt:  best.ExpiresAt,
	}
}

func confidenceRank(confidence string) int {
	switch confidence {
	case dnsConfidenceHigh:
		return 2
	case dnsConfidenceMedium:
		return 1
	default:
		return 0
	}
}

func lookupDNSCorrelation(
	ip net.IP,
	pid uint32,
	observedAt time.Time,
) *dnsCorrelationPayload {
	return activeDNSCorrelator.Lookup(ip, pid, observedAt)
}

func cloneDNSCorrelation(value *dnsCorrelationPayload) *dnsCorrelationPayload {
	if value == nil {
		return nil
	}

	copied := *value
	return &copied
}
