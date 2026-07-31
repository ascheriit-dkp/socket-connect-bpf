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
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const maxKernelFilterEntries = 1024

const (
	kernelFamilyFilterIPv4 uint32 = 1 << iota
	kernelFamilyFilterIPv6
	kernelFamilyFilterOther
)

type kernelFilterOptions struct {
	pids     pidFilterValues
	uids     uidFilterValues
	families familyFilterValues
	ports    portFilterValues
}

func (filters *kernelFilterOptions) register(flagSet *flag.FlagSet) {
	flagSet.Var(
		&filters.pids,
		"pid",
		"emit events for PID; may be repeated",
	)

	flagSet.Var(
		&filters.uids,
		"uid",
		"emit events for UID; may be repeated",
	)

	flagSet.Var(
		&filters.families,
		"family",
		"emit events for address family: ipv4, ipv6 or other; may be repeated",
	)

	flagSet.Var(
		&filters.ports,
		"port",
		"emit events for destination port; may be repeated",
	)
}

func (filters kernelFilterOptions) empty() bool {
	return len(filters.pids) == 0 &&
		len(filters.uids) == 0 &&
		filters.families == 0 &&
		len(filters.ports) == 0
}

func (filters kernelFilterOptions) hasPIDFilter() bool {
	return len(filters.pids) != 0
}

func (filters kernelFilterOptions) hasUIDFilter() bool {
	return len(filters.uids) != 0
}

func (filters kernelFilterOptions) hasFamilyFilter() bool {
	return filters.families != 0
}

func (filters kernelFilterOptions) hasPortFilter() bool {
	return len(filters.ports) != 0
}

func (filters kernelFilterOptions) familyMask() uint32 {
	return uint32(filters.families)
}

type pidFilterValues map[uint32]struct{}

func (values *pidFilterValues) Set(rawValue string) error {
	value, err := parseUnsignedFilterValue(
		rawValue,
		"pid",
		32,
	)
	if err != nil {
		return err
	}

	if value == 0 {
		return fmt.Errorf(
			"invalid --pid value %q: value must be greater than zero",
			rawValue,
		)
	}

	if *values == nil {
		*values = make(pidFilterValues)
	}

	parsedValue := uint32(value)

	if _, exists := (*values)[parsedValue]; exists {
		return nil
	}

	if len(*values) >= maxKernelFilterEntries {
		return fmt.Errorf(
			"--pid supports at most %d distinct values",
			maxKernelFilterEntries,
		)
	}

	(*values)[parsedValue] = struct{}{}

	return nil
}

func (values pidFilterValues) String() string {
	return formatUint32FilterValues(values)
}

func (values pidFilterValues) contains(value uint32) bool {
	_, exists := values[value]

	return exists
}

type uidFilterValues map[uint32]struct{}

func (values *uidFilterValues) Set(rawValue string) error {
	value, err := parseUnsignedFilterValue(
		rawValue,
		"uid",
		32,
	)
	if err != nil {
		return err
	}

	if *values == nil {
		*values = make(uidFilterValues)
	}

	parsedValue := uint32(value)

	if _, exists := (*values)[parsedValue]; exists {
		return nil
	}

	if len(*values) >= maxKernelFilterEntries {
		return fmt.Errorf(
			"--uid supports at most %d distinct values",
			maxKernelFilterEntries,
		)
	}

	(*values)[parsedValue] = struct{}{}

	return nil
}

func (values uidFilterValues) String() string {
	return formatUint32FilterValues(values)
}

func (values uidFilterValues) contains(value uint32) bool {
	_, exists := values[value]

	return exists
}

type portFilterValues map[uint16]struct{}

func (values *portFilterValues) Set(rawValue string) error {
	value, err := parseUnsignedFilterValue(
		rawValue,
		"port",
		16,
	)
	if err != nil {
		return err
	}

	if value == 0 {
		return fmt.Errorf(
			"invalid --port value %q: value must be greater than zero",
			rawValue,
		)
	}

	if *values == nil {
		*values = make(portFilterValues)
	}

	parsedValue := uint16(value)

	if _, exists := (*values)[parsedValue]; exists {
		return nil
	}

	if len(*values) >= maxKernelFilterEntries {
		return fmt.Errorf(
			"--port supports at most %d distinct values",
			maxKernelFilterEntries,
		)
	}

	(*values)[parsedValue] = struct{}{}

	return nil
}

func (values portFilterValues) String() string {
	if len(values) == 0 {
		return ""
	}

	sortedValues := make([]int, 0, len(values))

	for value := range values {
		sortedValues = append(
			sortedValues,
			int(value),
		)
	}

	sort.Ints(sortedValues)

	formattedValues := make(
		[]string,
		0,
		len(sortedValues),
	)

	for _, value := range sortedValues {
		formattedValues = append(
			formattedValues,
			strconv.Itoa(value),
		)
	}

	return strings.Join(formattedValues, ",")
}

func (values portFilterValues) contains(value uint16) bool {
	_, exists := values[value]

	return exists
}

type familyFilterValues uint32

func (values *familyFilterValues) Set(rawValue string) error {
	var mask uint32

	switch rawValue {
	case "ipv4":
		mask = kernelFamilyFilterIPv4

	case "ipv6":
		mask = kernelFamilyFilterIPv6

	case "other":
		mask = kernelFamilyFilterOther

	default:
		return fmt.Errorf(
			"invalid --family value %q: expected ipv4, ipv6 or other",
			rawValue,
		)
	}

	*values |= familyFilterValues(mask)

	return nil
}

func (values familyFilterValues) String() string {
	if values == 0 {
		return ""
	}

	formattedValues := make([]string, 0, 3)

	if uint32(values)&kernelFamilyFilterIPv4 != 0 {
		formattedValues = append(
			formattedValues,
			"ipv4",
		)
	}

	if uint32(values)&kernelFamilyFilterIPv6 != 0 {
		formattedValues = append(
			formattedValues,
			"ipv6",
		)
	}

	if uint32(values)&kernelFamilyFilterOther != 0 {
		formattedValues = append(
			formattedValues,
			"other",
		)
	}

	return strings.Join(formattedValues, ",")
}

func (values familyFilterValues) contains(mask uint32) bool {
	return uint32(values)&mask != 0
}

func parseUnsignedFilterValue(
	rawValue string,
	optionName string,
	bitSize int,
) (uint64, error) {
	if rawValue == "" {
		return 0, fmt.Errorf(
			"invalid --%s value %q: expected an unsigned decimal integer",
			optionName,
			rawValue,
		)
	}

	for _, character := range rawValue {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf(
				"invalid --%s value %q: expected an unsigned decimal integer",
				optionName,
				rawValue,
			)
		}
	}

	value, err := strconv.ParseUint(
		rawValue,
		10,
		bitSize,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid --%s value %q: outside the uint%d range",
			optionName,
			rawValue,
			bitSize,
		)
	}

	return value, nil
}

func formatUint32FilterValues[T ~map[uint32]struct{}](
	values T,
) string {
	if len(values) == 0 {
		return ""
	}

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

	formattedValues := make(
		[]string,
		0,
		len(sortedValues),
	)

	for _, value := range sortedValues {
		formattedValues = append(
			formattedValues,
			strconv.FormatUint(
				uint64(value),
				10,
			),
		)
	}

	return strings.Join(formattedValues, ",")
}
