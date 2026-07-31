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
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestKernelFilterConfigLayout(t *testing.T) {
	t.Parallel()

	var config kernelFilterConfig

	if got := binary.Size(config); got != kernelFilterConfigBinarySize {
		t.Fatalf(
			"binary size = %d; want %d",
			got,
			kernelFilterConfigBinarySize,
		)
	}

	if got := int(unsafe.Sizeof(config)); got != kernelFilterConfigBinarySize {
		t.Fatalf(
			"memory size = %d; want %d",
			got,
			kernelFilterConfigBinarySize,
		)
	}

	if got := unsafe.Offsetof(config.EnabledFilters); got != 0 {
		t.Fatalf(
			"EnabledFilters offset = %d; want 0",
			got,
		)
	}

	if got := unsafe.Offsetof(config.FamilyMask); got != 4 {
		t.Fatalf(
			"FamilyMask offset = %d; want 4",
			got,
		)
	}
}

func TestNewKernelFilterConfigEmpty(t *testing.T) {
	t.Parallel()

	config := newKernelFilterConfig(kernelFilterOptions{})

	expected := kernelFilterConfig{}

	if config != expected {
		t.Fatalf(
			"config = %+v; want %+v",
			config,
			expected,
		)
	}
}

func TestNewKernelFilterConfigEnablesConfiguredCategories(
	t *testing.T,
) {
	t.Parallel()

	filters := kernelFilterOptions{
		pids: pidFilterValues{
			1234: {},
		},
		uids: uidFilterValues{
			1000: {},
		},
		families: familyFilterValues(
			kernelFamilyFilterIPv4 |
				kernelFamilyFilterOther,
		),
		ports: portFilterValues{
			443: {},
		},
	}

	config := newKernelFilterConfig(filters)

	expected := kernelFilterConfig{
		EnabledFilters: kernelFilterPIDEnabled |
			kernelFilterUIDEnabled |
			kernelFilterFamilyEnabled |
			kernelFilterPortEnabled,
		FamilyMask: kernelFamilyFilterIPv4 |
			kernelFamilyFilterOther,
	}

	if config != expected {
		t.Fatalf(
			"config = %+v; want %+v",
			config,
			expected,
		)
	}
}

func TestNewKernelFilterConfigEnablesEachCategoryIndependently(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name    string
		filters kernelFilterOptions
		want    kernelFilterConfig
	}{
		{
			name: "PID",
			filters: kernelFilterOptions{
				pids: pidFilterValues{
					1234: {},
				},
			},
			want: kernelFilterConfig{
				EnabledFilters: kernelFilterPIDEnabled,
			},
		},
		{
			name: "UID",
			filters: kernelFilterOptions{
				uids: uidFilterValues{
					1000: {},
				},
			},
			want: kernelFilterConfig{
				EnabledFilters: kernelFilterUIDEnabled,
			},
		},
		{
			name: "family",
			filters: kernelFilterOptions{
				families: familyFilterValues(
					kernelFamilyFilterIPv6,
				),
			},
			want: kernelFilterConfig{
				EnabledFilters: kernelFilterFamilyEnabled,
				FamilyMask:     kernelFamilyFilterIPv6,
			},
		},
		{
			name: "port",
			filters: kernelFilterOptions{
				ports: portFilterValues{
					53: {},
				},
			},
			want: kernelFilterConfig{
				EnabledFilters: kernelFilterPortEnabled,
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := newKernelFilterConfig(test.filters)

			if got != test.want {
				t.Fatalf(
					"config = %+v; want %+v",
					got,
					test.want,
				)
			}
		})
	}
}

func TestConfigureKernelFiltersWritesMembershipBeforeConfig(
	t *testing.T,
) {
	t.Parallel()

	var writes []kernelFilterMapWrite

	maps := newRecordingKernelFilterMaps(&writes)

	filters := kernelFilterOptions{
		pids: pidFilterValues{
			300: {},
			100: {},
		},
		uids: uidFilterValues{
			1000: {},
			0:    {},
		},
		families: familyFilterValues(
			kernelFamilyFilterIPv4 |
				kernelFamilyFilterOther,
		),
		ports: portFilterValues{
			443: {},
			80:  {},
		},
	}

	if err := configureKernelFilters(filters, maps); err != nil {
		t.Fatalf(
			"configuring kernel filters: %v",
			err,
		)
	}

	expectedWrites := []kernelFilterMapWrite{
		{
			mapName: "pids",
			key:     uint32(100),
			value:   kernelFilterMembershipValue,
		},
		{
			mapName: "pids",
			key:     uint32(300),
			value:   kernelFilterMembershipValue,
		},
		{
			mapName: "uids",
			key:     uint32(0),
			value:   kernelFilterMembershipValue,
		},
		{
			mapName: "uids",
			key:     uint32(1000),
			value:   kernelFilterMembershipValue,
		},
		{
			mapName: "ports",
			key:     uint16(80),
			value:   kernelFilterMembershipValue,
		},
		{
			mapName: "ports",
			key:     uint16(443),
			value:   kernelFilterMembershipValue,
		},
		{
			mapName: "config",
			key:     kernelFilterConfigKey,
			value: kernelFilterConfig{
				EnabledFilters: kernelFilterPIDEnabled |
					kernelFilterUIDEnabled |
					kernelFilterFamilyEnabled |
					kernelFilterPortEnabled,
				FamilyMask: kernelFamilyFilterIPv4 |
					kernelFamilyFilterOther,
			},
		},
	}

	requireKernelFilterWritesEqual(
		t,
		writes,
		expectedWrites,
	)
}

func TestConfigureKernelFiltersEmptyWritesDisabledConfig(
	t *testing.T,
) {
	t.Parallel()

	var writes []kernelFilterMapWrite

	maps := newRecordingKernelFilterMaps(&writes)

	if err := configureKernelFilters(
		kernelFilterOptions{},
		maps,
	); err != nil {
		t.Fatalf(
			"configuring empty kernel filters: %v",
			err,
		)
	}

	expectedWrites := []kernelFilterMapWrite{
		{
			mapName: "config",
			key:     kernelFilterConfigKey,
			value:   kernelFilterConfig{},
		},
	}

	requireKernelFilterWritesEqual(
		t,
		writes,
		expectedWrites,
	)
}

func TestConfigureKernelFiltersStopsBeforeConfigOnMembershipFailure(
	t *testing.T,
) {
	t.Parallel()

	sentinel := errors.New("membership write failed")

	tests := []struct {
		name          string
		filters       kernelFilterOptions
		configureMaps func(
			*[]kernelFilterMapWrite,
			*recordingKernelFilterMap,
			*recordingKernelFilterMap,
			*recordingKernelFilterMap,
			*recordingKernelFilterMap,
		)
		wantError      string
		expectedWrites []kernelFilterMapWrite
	}{
		{
			name: "PID",
			filters: kernelFilterOptions{
				pids: pidFilterValues{
					100: {},
				},
				uids: uidFilterValues{
					1000: {},
				},
			},
			configureMaps: func(
				_ *[]kernelFilterMapWrite,
				_ *recordingKernelFilterMap,
				pids *recordingKernelFilterMap,
				_ *recordingKernelFilterMap,
				_ *recordingKernelFilterMap,
			) {
				pids.failAtCall = 1
				pids.failure = sentinel
			},
			wantError: "populate PID filter map with PID 100",
			expectedWrites: []kernelFilterMapWrite{
				{
					mapName: "pids",
					key:     uint32(100),
					value:   kernelFilterMembershipValue,
				},
			},
		},
		{
			name: "UID",
			filters: kernelFilterOptions{
				pids: pidFilterValues{
					100: {},
				},
				uids: uidFilterValues{
					1000: {},
				},
				ports: portFilterValues{
					443: {},
				},
			},
			configureMaps: func(
				_ *[]kernelFilterMapWrite,
				_ *recordingKernelFilterMap,
				_ *recordingKernelFilterMap,
				uids *recordingKernelFilterMap,
				_ *recordingKernelFilterMap,
			) {
				uids.failAtCall = 1
				uids.failure = sentinel
			},
			wantError: "populate UID filter map with UID 1000",
			expectedWrites: []kernelFilterMapWrite{
				{
					mapName: "pids",
					key:     uint32(100),
					value:   kernelFilterMembershipValue,
				},
				{
					mapName: "uids",
					key:     uint32(1000),
					value:   kernelFilterMembershipValue,
				},
			},
		},
		{
			name: "port",
			filters: kernelFilterOptions{
				pids: pidFilterValues{
					100: {},
				},
				uids: uidFilterValues{
					1000: {},
				},
				ports: portFilterValues{
					443: {},
				},
			},
			configureMaps: func(
				_ *[]kernelFilterMapWrite,
				_ *recordingKernelFilterMap,
				_ *recordingKernelFilterMap,
				_ *recordingKernelFilterMap,
				ports *recordingKernelFilterMap,
			) {
				ports.failAtCall = 1
				ports.failure = sentinel
			},
			wantError: "populate destination-port filter map with port 443",
			expectedWrites: []kernelFilterMapWrite{
				{
					mapName: "pids",
					key:     uint32(100),
					value:   kernelFilterMembershipValue,
				},
				{
					mapName: "uids",
					key:     uint32(1000),
					value:   kernelFilterMembershipValue,
				},
				{
					mapName: "ports",
					key:     uint16(443),
					value:   kernelFilterMembershipValue,
				},
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var writes []kernelFilterMapWrite

			config := &recordingKernelFilterMap{
				name:   "config",
				writes: &writes,
			}
			pids := &recordingKernelFilterMap{
				name:   "pids",
				writes: &writes,
			}
			uids := &recordingKernelFilterMap{
				name:   "uids",
				writes: &writes,
			}
			ports := &recordingKernelFilterMap{
				name:   "ports",
				writes: &writes,
			}

			test.configureMaps(
				&writes,
				config,
				pids,
				uids,
				ports,
			)

			err := configureKernelFilters(
				test.filters,
				kernelFilterMaps{
					config: config,
					pids:   pids,
					uids:   uids,
					ports:  ports,
				},
			)

			requireKernelFilterError(
				t,
				err,
				test.wantError,
				sentinel,
			)

			requireKernelFilterWritesEqual(
				t,
				writes,
				test.expectedWrites,
			)

			for _, write := range writes {
				if write.mapName == "config" {
					t.Fatal(
						"configuration map was written after membership failure",
					)
				}
			}
		})
	}
}

func TestConfigureKernelFiltersReportsConfigFailureLast(
	t *testing.T,
) {
	t.Parallel()

	sentinel := errors.New("configuration write failed")

	var writes []kernelFilterMapWrite

	config := &recordingKernelFilterMap{
		name:       "config",
		writes:     &writes,
		failAtCall: 1,
		failure:    sentinel,
	}
	pids := &recordingKernelFilterMap{
		name:   "pids",
		writes: &writes,
	}
	uids := &recordingKernelFilterMap{
		name:   "uids",
		writes: &writes,
	}
	ports := &recordingKernelFilterMap{
		name:   "ports",
		writes: &writes,
	}

	filters := kernelFilterOptions{
		pids: pidFilterValues{
			1234: {},
		},
		uids: uidFilterValues{
			1000: {},
		},
		ports: portFilterValues{
			443: {},
		},
	}

	err := configureKernelFilters(
		filters,
		kernelFilterMaps{
			config: config,
			pids:   pids,
			uids:   uids,
			ports:  ports,
		},
	)

	requireKernelFilterError(
		t,
		err,
		"write kernel filter configuration",
		sentinel,
	)

	if got := len(writes); got != 4 {
		t.Fatalf(
			"write count = %d; want 4",
			got,
		)
	}

	lastWrite := writes[len(writes)-1]

	if lastWrite.mapName != "config" {
		t.Fatalf(
			"last write map = %q; want config",
			lastWrite.mapName,
		)
	}
}

type kernelFilterMapWrite struct {
	mapName string
	key     interface{}
	value   interface{}
}

type recordingKernelFilterMap struct {
	name       string
	writes     *[]kernelFilterMapWrite
	calls      int
	failAtCall int
	failure    error
}

func (filterMap *recordingKernelFilterMap) Put(
	key interface{},
	value interface{},
) error {
	filterMap.calls++

	*filterMap.writes = append(
		*filterMap.writes,
		kernelFilterMapWrite{
			mapName: filterMap.name,
			key:     key,
			value:   value,
		},
	)

	if filterMap.failAtCall != 0 &&
		filterMap.calls == filterMap.failAtCall {
		return filterMap.failure
	}

	return nil
}

func newRecordingKernelFilterMaps(
	writes *[]kernelFilterMapWrite,
) kernelFilterMaps {
	return kernelFilterMaps{
		config: &recordingKernelFilterMap{
			name:   "config",
			writes: writes,
		},
		pids: &recordingKernelFilterMap{
			name:   "pids",
			writes: writes,
		},
		uids: &recordingKernelFilterMap{
			name:   "uids",
			writes: writes,
		},
		ports: &recordingKernelFilterMap{
			name:   "ports",
			writes: writes,
		},
	}
}

func requireKernelFilterWritesEqual(
	t *testing.T,
	got []kernelFilterMapWrite,
	want []kernelFilterMapWrite,
) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"writes = %#v; want %#v",
			got,
			want,
		)
	}
}

func requireKernelFilterError(
	t *testing.T,
	err error,
	expectedSubstring string,
	expectedCause error,
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

	if !errors.Is(err, expectedCause) {
		t.Fatalf(
			"error = %q; want wrapped cause %q",
			err,
			expectedCause,
		)
	}
}
