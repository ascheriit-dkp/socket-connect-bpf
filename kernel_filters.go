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
	"fmt"
	"sort"
)

const (
	kernelFilterConfigKey       uint32 = 0
	kernelFilterMembershipValue uint8  = 1

	kernelFilterConfigBinarySize = 8
)

const (
	kernelFilterPIDEnabled uint32 = 1 << iota
	kernelFilterUIDEnabled
	kernelFilterFamilyEnabled
	kernelFilterPortEnabled
)

// kernelFilterConfig is the userspace representation of filter_config_t in
// the eBPF program.
type kernelFilterConfig struct {
	EnabledFilters uint32
	FamilyMask     uint32
}

// kernelFilterMap is implemented by *ebpf.Map.
//
// Keeping the configuration logic behind this small interface allows its
// ordering and failure behaviour to be tested without creating kernel maps.
type kernelFilterMap interface {
	Put(key interface{}, value interface{}) error
}

type kernelFilterMaps struct {
	config kernelFilterMap
	pids   kernelFilterMap
	uids   kernelFilterMap
	ports  kernelFilterMap
}

func newKernelFilterConfig(
	filters kernelFilterOptions,
) kernelFilterConfig {
	var enabledFilters uint32

	if filters.hasPIDFilter() {
		enabledFilters |= kernelFilterPIDEnabled
	}

	if filters.hasUIDFilter() {
		enabledFilters |= kernelFilterUIDEnabled
	}

	if filters.hasFamilyFilter() {
		enabledFilters |= kernelFilterFamilyEnabled
	}

	if filters.hasPortFilter() {
		enabledFilters |= kernelFilterPortEnabled
	}

	return kernelFilterConfig{
		EnabledFilters: enabledFilters,
		FamilyMask:     filters.familyMask(),
	}
}

// configureKernelFilters writes membership maps before enabling their
// corresponding categories in the configuration map.
//
// Userspace must call this function before attaching the BPF probe.
func configureKernelFilters(
	filters kernelFilterOptions,
	maps kernelFilterMaps,
) error {
	for _, pid := range sortedUint32KernelFilterValues(
		filters.pids,
	) {
		if err := maps.pids.Put(
			pid,
			kernelFilterMembershipValue,
		); err != nil {
			return fmt.Errorf(
				"populate PID filter map with PID %d: %w",
				pid,
				err,
			)
		}
	}

	for _, uid := range sortedUint32KernelFilterValues(
		filters.uids,
	) {
		if err := maps.uids.Put(
			uid,
			kernelFilterMembershipValue,
		); err != nil {
			return fmt.Errorf(
				"populate UID filter map with UID %d: %w",
				uid,
				err,
			)
		}
	}

	for _, port := range sortedPortKernelFilterValues(
		filters.ports,
	) {
		if err := maps.ports.Put(
			port,
			kernelFilterMembershipValue,
		); err != nil {
			return fmt.Errorf(
				"populate destination-port filter map with port %d: %w",
				port,
				err,
			)
		}
	}

	config := newKernelFilterConfig(filters)

	if err := maps.config.Put(
		kernelFilterConfigKey,
		config,
	); err != nil {
		return fmt.Errorf(
			"write kernel filter configuration: %w",
			err,
		)
	}

	return nil
}

func sortedUint32KernelFilterValues[
	T ~map[uint32]struct{},
](values T) []uint32 {
	sortedValues := make(
		[]uint32,
		0,
		len(values),
	)

	for value := range values {
		sortedValues = append(
			sortedValues,
			value,
		)
	}

	sort.Slice(
		sortedValues,
		func(left int, right int) bool {
			return sortedValues[left] < sortedValues[right]
		},
	)

	return sortedValues
}

func sortedPortKernelFilterValues(
	values portFilterValues,
) []uint16 {
	sortedValues := make(
		[]uint16,
		0,
		len(values),
	)

	for value := range values {
		sortedValues = append(
			sortedValues,
			value,
		)
	}

	sort.Slice(
		sortedValues,
		func(left int, right int) bool {
			return sortedValues[left] < sortedValues[right]
		},
	)

	return sortedValues
}
