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
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var benchmarkSanitizedField string

func BenchmarkSanitizeTerminalField(b *testing.B) {
	testCases := []struct {
		name  string
		value string
	}{
		{
			name:  "clean",
			value: "/usr/bin/curl --silent https://example.com/api",
		},
		{
			name: "control_characters",
			value: "curl\t--header\nAuthorization:\x1b[31msecret\r",
		},
		{
			name:  "unicode",
			value: "工具/网络—δοκιμή\u2066hidden\u2069",
		},
		{
			name:  "long_arguments",
			value: strings.Repeat("argument=value ", 32),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		b.Run(testCase.name, func(b *testing.B) {
			b.ReportAllocs()

			for iteration := 0; iteration < b.N; iteration++ {
				benchmarkSanitizedField = sanitizeTerminalField(
					testCase.value,
				)
			}
		})
	}
}

func BenchmarkOutputPrintLine(b *testing.B) {
	event := benchmarkEventPayload()

	outputFactories := []struct {
		name string
		new  func(io.Writer) output
	}{
		{
			name: "table/basic",
			new: func(writer io.Writer) output {
				return newTableOutputWithWriter(false, writer)
			},
		},
		{
			name: "table/extended",
			new: func(writer io.Writer) output {
				return newTableOutputWithWriter(true, writer)
			},
		},
		{
			name: "ndjson/basic",
			new: func(writer io.Writer) output {
				return newNDJSONOutputWithWriter(false, writer)
			},
		},
		{
			name: "ndjson/extended",
			new: func(writer io.Writer) output {
				return newNDJSONOutputWithWriter(true, writer)
			},
		},
	}

	for _, outputFactory := range outputFactories {
		outputFactory := outputFactory

		b.Run(outputFactory.name+"/serial", func(b *testing.B) {
			benchmarkOutput := outputFactory.new(io.Discard)

			b.ReportAllocs()
			b.ResetTimer()

			for iteration := 0; iteration < b.N; iteration++ {
				benchmarkOutput.PrintLine(event)
			}
		})

		b.Run(outputFactory.name+"/parallel", func(b *testing.B) {
			benchmarkOutput := outputFactory.new(io.Discard)

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(worker *testing.PB) {
				for worker.Next() {
					benchmarkOutput.PrintLine(event)
				}
			})
		})
	}
}

func benchmarkEventPayload() eventPayload {
	return eventPayload{
		KernelTime:    "123456789",
		GoTime:        time.Date(2026, 7, 30, 9, 0, 0, 123456789, time.UTC),
		AddressFamily: "AF_INET",
		Pid:           4242,
		ProcessPath:   "/usr/bin/curl",
		ProcessArgs: "curl --fail --silent --show-error " +
			"https://example.com/api?token=[redacted]",
		User:     "benchmark",
		Comm:     "curl",
		DestIP:   net.ParseIP("203.0.113.42").To4(),
		DestPort: 443,
		ASNameInfo: ASNameInfo{
			AsNumber: 64500,
			Name:     "EXAMPLE",
		},
	}
}
