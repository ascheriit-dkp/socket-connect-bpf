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
	"io"
	"strconv"
	"strings"
	"testing"
)

const (
	maxUint32FilterTestValue = ^uint32(0)
	maxUint16FilterTestValue = ^uint16(0)
)

func TestKernelFilterOptionsRegisterRepeatedValues(t *testing.T) {
	t.Parallel()

	var filters kernelFilterOptions

	flagSet := flag.NewFlagSet(
		"kernel-filter-options",
		flag.ContinueOnError,
	)
	flagSet.SetOutput(io.Discard)

	filters.register(flagSet)

	err := flagSet.Parse([]string{
		"--pid", "5678",
		"--pid", "1234",
		"--pid", "5678",
		"--uid", "1000",
		"--uid", "0",
		"--uid", "1000",
		"--family", "ipv6",
		"--family", "ipv4",
		"--family", "ipv6",
		"--port", "443",
		"--port", "80",
		"--port", "443",
	})
	if err != nil {
		t.Fatalf("parsing repeated filter options: %v", err)
	}

	if remainingArguments := flagSet.Args(); len(remainingArguments) != 0 {
		t.Fatalf(
			"remaining arguments = %v; want none",
			remainingArguments,
		)
	}

	if got := len(filters.pids); got != 2 {
		t.Fatalf("PID filter count = %d; want 2", got)
	}

	if !filters.pids.contains(1234) ||
		!filters.pids.contains(5678) {
		t.Fatalf(
			"PID filters = %q; want 1234 and 5678",
			filters.pids.String(),
		)
	}

	if got := filters.pids.String(); got != "1234,5678" {
		t.Fatalf(
			"formatted PID filters = %q; want %q",
			got,
			"1234,5678",
		)
	}

	if got := len(filters.uids); got != 2 {
		t.Fatalf("UID filter count = %d; want 2", got)
	}

	if !filters.uids.contains(0) ||
		!filters.uids.contains(1000) {
		t.Fatalf(
			"UID filters = %q; want 0 and 1000",
			filters.uids.String(),
		)
	}

	if got := filters.uids.String(); got != "0,1000" {
		t.Fatalf(
			"formatted UID filters = %q; want %q",
			got,
			"0,1000",
		)
	}

	expectedFamilyMask := kernelFamilyFilterIPv4 |
		kernelFamilyFilterIPv6

	if got := filters.familyMask(); got != expectedFamilyMask {
		t.Fatalf(
			"family mask = %d; want %d",
			got,
			expectedFamilyMask,
		)
	}

	if got := filters.families.String(); got != "ipv4,ipv6" {
		t.Fatalf(
			"formatted family filters = %q; want %q",
			got,
			"ipv4,ipv6",
		)
	}

	if got := len(filters.ports); got != 2 {
		t.Fatalf("port filter count = %d; want 2", got)
	}

	if !filters.ports.contains(80) ||
		!filters.ports.contains(443) {
		t.Fatalf(
			"port filters = %q; want 80 and 443",
			filters.ports.String(),
		)
	}

	if got := filters.ports.String(); got != "80,443" {
		t.Fatalf(
			"formatted port filters = %q; want %q",
			got,
			"80,443",
		)
	}

	if filters.empty() {
		t.Fatal("configured filters reported empty")
	}

	if !filters.hasPIDFilter() {
		t.Fatal("configured PID filter reported disabled")
	}

	if !filters.hasUIDFilter() {
		t.Fatal("configured UID filter reported disabled")
	}

	if !filters.hasFamilyFilter() {
		t.Fatal("configured family filter reported disabled")
	}

	if !filters.hasPortFilter() {
		t.Fatal("configured port filter reported disabled")
	}
}

func TestKernelFilterOptionsRegisterRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	var filters kernelFilterOptions

	flagSet := flag.NewFlagSet(
		"invalid-kernel-filter-option",
		flag.ContinueOnError,
	)
	flagSet.SetOutput(io.Discard)

	filters.register(flagSet)

	err := flagSet.Parse([]string{
		"--pid",
		"0",
	})
	requireFilterErrorContains(
		t,
		err,
		"greater than zero",
	)
}

func TestKernelFilterOptionsEmpty(t *testing.T) {
	t.Parallel()

	var filters kernelFilterOptions

	if !filters.empty() {
		t.Fatal("zero-value filters reported non-empty")
	}

	if filters.hasPIDFilter() {
		t.Fatal("zero-value PID filter reported enabled")
	}

	if filters.hasUIDFilter() {
		t.Fatal("zero-value UID filter reported enabled")
	}

	if filters.hasFamilyFilter() {
		t.Fatal("zero-value family filter reported enabled")
	}

	if filters.hasPortFilter() {
		t.Fatal("zero-value port filter reported enabled")
	}

	if got := filters.familyMask(); got != 0 {
		t.Fatalf("zero-value family mask = %d; want 0", got)
	}
}

func TestKernelFilterOptionsDetectEachCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		filters          kernelFilterOptions
		wantPIDFilter    bool
		wantUIDFilter    bool
		wantFamilyFilter bool
		wantPortFilter   bool
		wantFamilyMask   uint32
	}{
		{
			name: "PID",
			filters: kernelFilterOptions{
				pids: pidFilterValues{
					1234: struct{}{},
				},
			},
			wantPIDFilter: true,
		},
		{
			name: "UID",
			filters: kernelFilterOptions{
				uids: uidFilterValues{
					1000: struct{}{},
				},
			},
			wantUIDFilter: true,
		},
		{
			name: "family",
			filters: kernelFilterOptions{
				families: familyFilterValues(
					kernelFamilyFilterIPv6,
				),
			},
			wantFamilyFilter: true,
			wantFamilyMask:   kernelFamilyFilterIPv6,
		},
		{
			name: "port",
			filters: kernelFilterOptions{
				ports: portFilterValues{
					443: struct{}{},
				},
			},
			wantPortFilter: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.filters.empty() {
				t.Fatal("configured filter reported empty")
			}

			if got := test.filters.hasPIDFilter();
				got != test.wantPIDFilter {
				t.Fatalf(
					"PID filter enabled = %t; want %t",
					got,
					test.wantPIDFilter,
				)
			}

			if got := test.filters.hasUIDFilter();
				got != test.wantUIDFilter {
				t.Fatalf(
					"UID filter enabled = %t; want %t",
					got,
					test.wantUIDFilter,
				)
			}

			if got := test.filters.hasFamilyFilter();
				got != test.wantFamilyFilter {
				t.Fatalf(
					"family filter enabled = %t; want %t",
					got,
					test.wantFamilyFilter,
				)
			}

			if got := test.filters.hasPortFilter();
				got != test.wantPortFilter {
				t.Fatalf(
					"port filter enabled = %t; want %t",
					got,
					test.wantPortFilter,
				)
			}

			if got := test.filters.familyMask();
				got != test.wantFamilyMask {
				t.Fatalf(
					"family mask = %d; want %d",
					got,
					test.wantFamilyMask,
				)
			}
		})
	}
}

func TestPIDFilterValuesAcceptBoundariesAndDuplicates(t *testing.T) {
	t.Parallel()

	var values pidFilterValues

	maximumValue := strconv.FormatUint(
		uint64(maxUint32FilterTestValue),
		10,
	)

	for _, rawValue := range []string{
		"1",
		maximumValue,
		"1",
		"0001",
	} {
		if err := values.Set(rawValue); err != nil {
			t.Fatalf(
				"setting valid PID %q: %v",
				rawValue,
				err,
			)
		}
	}

	if got := len(values); got != 2 {
		t.Fatalf("PID filter count = %d; want 2", got)
	}

	if !values.contains(1) {
		t.Fatal("PID filters do not contain 1")
	}

	if !values.contains(maxUint32FilterTestValue) {
		t.Fatalf(
			"PID filters do not contain %d",
			maxUint32FilterTestValue,
		)
	}

	expected := "1," + maximumValue
	if got := values.String(); got != expected {
		t.Fatalf(
			"formatted PID filters = %q; want %q",
			got,
			expected,
		)
	}
}

func TestPIDFilterValuesRejectInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rawValue  string
		wantError string
	}{
		{
			rawValue:  "",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "0",
			wantError: "greater than zero",
		},
		{
			rawValue:  "-1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "+1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  " 1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "1 ",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "1.0",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "4294967296",
			wantError: "outside the uint32 range",
		},
	}

	for _, test := range tests {
		test := test

		t.Run("value_"+strconv.Quote(test.rawValue), func(t *testing.T) {
			t.Parallel()

			var values pidFilterValues

			err := values.Set(test.rawValue)
			requireFilterErrorContains(
				t,
				err,
				test.wantError,
			)
		})
	}
}

func TestUIDFilterValuesAcceptBoundariesAndDuplicates(t *testing.T) {
	t.Parallel()

	var values uidFilterValues

	maximumValue := strconv.FormatUint(
		uint64(maxUint32FilterTestValue),
		10,
	)

	for _, rawValue := range []string{
		"0",
		maximumValue,
		"0",
		"0000",
	} {
		if err := values.Set(rawValue); err != nil {
			t.Fatalf(
				"setting valid UID %q: %v",
				rawValue,
				err,
			)
		}
	}

	if got := len(values); got != 2 {
		t.Fatalf("UID filter count = %d; want 2", got)
	}

	if !values.contains(0) {
		t.Fatal("UID filters do not contain 0")
	}

	if !values.contains(maxUint32FilterTestValue) {
		t.Fatalf(
			"UID filters do not contain %d",
			maxUint32FilterTestValue,
		)
	}

	expected := "0," + maximumValue
	if got := values.String(); got != expected {
		t.Fatalf(
			"formatted UID filters = %q; want %q",
			got,
			expected,
		)
	}
}

func TestUIDFilterValuesRejectInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rawValue  string
		wantError string
	}{
		{
			rawValue:  "",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "-1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "+1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "root",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "4294967296",
			wantError: "outside the uint32 range",
		},
	}

	for _, test := range tests {
		test := test

		t.Run("value_"+strconv.Quote(test.rawValue), func(t *testing.T) {
			t.Parallel()

			var values uidFilterValues

			err := values.Set(test.rawValue)
			requireFilterErrorContains(
				t,
				err,
				test.wantError,
			)
		})
	}
}

func TestPortFilterValuesAcceptBoundariesAndDuplicates(t *testing.T) {
	t.Parallel()

	var values portFilterValues

	maximumValue := strconv.FormatUint(
		uint64(maxUint16FilterTestValue),
		10,
	)

	for _, rawValue := range []string{
		"1",
		maximumValue,
		"1",
		"0001",
	} {
		if err := values.Set(rawValue); err != nil {
			t.Fatalf(
				"setting valid port %q: %v",
				rawValue,
				err,
			)
		}
	}

	if got := len(values); got != 2 {
		t.Fatalf("port filter count = %d; want 2", got)
	}

	if !values.contains(1) {
		t.Fatal("port filters do not contain 1")
	}

	if !values.contains(maxUint16FilterTestValue) {
		t.Fatalf(
			"port filters do not contain %d",
			maxUint16FilterTestValue,
		)
	}

	expected := "1," + maximumValue
	if got := values.String(); got != expected {
		t.Fatalf(
			"formatted port filters = %q; want %q",
			got,
			expected,
		)
	}
}

func TestPortFilterValuesRejectInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rawValue  string
		wantError string
	}{
		{
			rawValue:  "",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "0",
			wantError: "greater than zero",
		},
		{
			rawValue:  "-1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "+1",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "1.0",
			wantError: "unsigned decimal integer",
		},
		{
			rawValue:  "65536",
			wantError: "outside the uint16 range",
		},
	}

	for _, test := range tests {
		test := test

		t.Run("value_"+strconv.Quote(test.rawValue), func(t *testing.T) {
			t.Parallel()

			var values portFilterValues

			err := values.Set(test.rawValue)
			requireFilterErrorContains(
				t,
				err,
				test.wantError,
			)
		})
	}
}

func TestFamilyFilterValuesAcceptAllCategoriesAndDuplicates(
	t *testing.T,
) {
	t.Parallel()

	var values familyFilterValues

	for _, rawValue := range []string{
		"ipv6",
		"other",
		"ipv4",
		"ipv6",
	} {
		if err := values.Set(rawValue); err != nil {
			t.Fatalf(
				"setting valid family %q: %v",
				rawValue,
				err,
			)
		}
	}

	expectedMask := kernelFamilyFilterIPv4 |
		kernelFamilyFilterIPv6 |
		kernelFamilyFilterOther

	if got := uint32(values); got != expectedMask {
		t.Fatalf(
			"family mask = %d; want %d",
			got,
			expectedMask,
		)
	}

	if !values.contains(kernelFamilyFilterIPv4) {
		t.Fatal("family filters do not contain IPv4")
	}

	if !values.contains(kernelFamilyFilterIPv6) {
		t.Fatal("family filters do not contain IPv6")
	}

	if !values.contains(kernelFamilyFilterOther) {
		t.Fatal("family filters do not contain other")
	}

	if got := values.String(); got != "ipv4,ipv6,other" {
		t.Fatalf(
			"formatted family filters = %q; want %q",
			got,
			"ipv4,ipv6,other",
		)
	}
}

func TestFamilyFilterValuesRejectInvalidValues(t *testing.T) {
	t.Parallel()

	for _, rawValue := range []string{
		"",
		"IPv4",
		"IPV6",
		"inet",
		"all",
		"other ",
	} {
		rawValue := rawValue

		t.Run("value_"+strconv.Quote(rawValue), func(t *testing.T) {
			t.Parallel()

			var values familyFilterValues

			err := values.Set(rawValue)
			requireFilterErrorContains(
				t,
				err,
				"expected ipv4, ipv6 or other",
			)
		})
	}
}

func TestPIDFilterValuesEnforceCapacity(t *testing.T) {
	t.Parallel()

	values := make(
		pidFilterValues,
		maxKernelFilterEntries,
	)

	for value := 1; value <= maxKernelFilterEntries; value++ {
		values[uint32(value)] = struct{}{}
	}

	if err := values.Set("1"); err != nil {
		t.Fatalf(
			"setting duplicate PID at capacity: %v",
			err,
		)
	}

	err := values.Set(
		strconv.Itoa(maxKernelFilterEntries + 1),
	)
	requireFilterErrorContains(
		t,
		err,
		"at most 1024 distinct values",
	)
}

func TestUIDFilterValuesEnforceCapacity(t *testing.T) {
	t.Parallel()

	values := make(
		uidFilterValues,
		maxKernelFilterEntries,
	)

	for value := 0; value < maxKernelFilterEntries; value++ {
		values[uint32(value)] = struct{}{}
	}

	if err := values.Set("0"); err != nil {
		t.Fatalf(
			"setting duplicate UID at capacity: %v",
			err,
		)
	}

	err := values.Set(
		strconv.Itoa(maxKernelFilterEntries),
	)
	requireFilterErrorContains(
		t,
		err,
		"at most 1024 distinct values",
	)
}

func TestPortFilterValuesEnforceCapacity(t *testing.T) {
	t.Parallel()

	values := make(
		portFilterValues,
		maxKernelFilterEntries,
	)

	for value := 1; value <= maxKernelFilterEntries; value++ {
		values[uint16(value)] = struct{}{}
	}

	if err := values.Set("1"); err != nil {
		t.Fatalf(
			"setting duplicate port at capacity: %v",
			err,
		)
	}

	err := values.Set(
		strconv.Itoa(maxKernelFilterEntries + 1),
	)
	requireFilterErrorContains(
		t,
		err,
		"at most 1024 distinct values",
	)
}

func requireFilterErrorContains(
	t *testing.T,
	err error,
	expectedSubstring string,
) {
	t.Helper()

	if err == nil {
		t.Fatalf(
			"error = nil; want substring %q",
			expectedSubstring,
		)
	}

	if !strings.Contains(err.Error(), expectedSubstring) {
		t.Fatalf(
			"error = %q; want substring %q",
			err,
			expectedSubstring,
		)
	}
}
