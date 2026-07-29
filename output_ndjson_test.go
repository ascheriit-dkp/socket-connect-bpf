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
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewOutputForFormat(t *testing.T) {
	t.Parallel()

	tableFormats := []string{
		"",
		"table",
		" TABLE ",
	}

	for _, format := range tableFormats {
		format := format

		t.Run("table_"+format, func(t *testing.T) {
			t.Parallel()

			selectedOutput, err := newOutputForFormat(format, false)
			if err != nil {
				t.Fatalf(
					"newOutputForFormat(%q) returned error: %v",
					format,
					err,
				)
			}

			if _, ok := selectedOutput.(*tableOutput); !ok {
				t.Fatalf(
					"newOutputForFormat(%q) returned %T; want *tableOutput",
					format,
					selectedOutput,
				)
			}
		})
	}

	ndjsonFormats := []string{
		"ndjson",
		" NDJSON ",
	}

	for _, format := range ndjsonFormats {
		format := format

		t.Run("ndjson_"+format, func(t *testing.T) {
			t.Parallel()

			selectedOutput, err := newOutputForFormat(format, false)
			if err != nil {
				t.Fatalf(
					"newOutputForFormat(%q) returned error: %v",
					format,
					err,
				)
			}

			if _, ok := selectedOutput.(*ndjsonOutput); !ok {
				t.Fatalf(
					"newOutputForFormat(%q) returned %T; want *ndjsonOutput",
					format,
					selectedOutput,
				)
			}
		})
	}
}

func TestNewOutputForFormatRejectsUnsupportedFormat(t *testing.T) {
	t.Parallel()

	selectedOutput, err := newOutputForFormat("xml", false)
	if err == nil {
		t.Fatal("newOutputForFormat(\"xml\") returned no error")
	}

	if selectedOutput != nil {
		t.Fatalf(
			"newOutputForFormat(\"xml\") returned %T; want nil",
			selectedOutput,
		)
	}

	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf(
			"unexpected error message: %q",
			err.Error(),
		)
	}
}

func TestNDJSONOutputWithoutExtendedFields(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	formatter := newNDJSONOutputWithWriter(false, &buffer)
	formatter.PrintHeader()

	if buffer.Len() != 0 {
		t.Fatalf(
			"NDJSON header wrote %q; want no output",
			buffer.String(),
		)
	}

	event := sampleNDJSONEventPayload()
	formatter.PrintLine(event)

	output := buffer.String()

	if strings.Count(output, "\n") != 1 {
		t.Fatalf(
			"NDJSON output should contain exactly one line: %q",
			output,
		)
	}

	if strings.Contains(output, `"arguments"`) {
		t.Fatalf(
			"arguments field present without extended output: %q",
			output,
		)
	}

	if strings.Contains(output, `"asn"`) {
		t.Fatalf(
			"ASN field present without extended output: %q",
			output,
		)
	}

	var decoded ndjsonEvent
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &decoded); err != nil {
		t.Fatalf("decoding NDJSON event: %v", err)
	}

	assertBaseNDJSONEvent(t, decoded)
}

func TestNDJSONOutputWithExtendedFields(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	formatter := newNDJSONOutputWithWriter(true, &buffer)
	event := sampleNDJSONEventPayload()

	formatter.PrintLine(event)

	output := buffer.String()

	if strings.Count(output, "\n") != 1 {
		t.Fatalf(
			"NDJSON output should contain exactly one line: %q",
			output,
		)
	}

	// The encoded JSON must not contain a raw embedded newline from the
	// process arguments.
	if strings.Contains(
		strings.TrimSuffix(output, "\n"),
		"first line\nsecond line",
	) {
		t.Fatalf(
			"NDJSON contains a raw newline inside an event: %q",
			output,
		)
	}

	var decoded ndjsonEvent
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &decoded); err != nil {
		t.Fatalf("decoding NDJSON event: %v", err)
	}

	assertBaseNDJSONEvent(t, decoded)

	if decoded.Process.Arguments != event.ProcessArgs {
		t.Fatalf(
			"arguments = %q; want %q",
			decoded.Process.Arguments,
			event.ProcessArgs,
		)
	}

	if decoded.ASN == nil {
		t.Fatal("ASN is nil; want extended ASN information")
	}

	if decoded.ASN.Number != event.ASNameInfo.AsNumber {
		t.Fatalf(
			"ASN number = %d; want %d",
			decoded.ASN.Number,
			event.ASNameInfo.AsNumber,
		)
	}

	if decoded.ASN.Name != event.ASNameInfo.Name {
		t.Fatalf(
			"ASN name = %q; want %q",
			decoded.ASN.Name,
			event.ASNameInfo.Name,
		)
	}
}

func assertBaseNDJSONEvent(t *testing.T, decoded ndjsonEvent) {
	t.Helper()

	event := sampleNDJSONEventPayload()

	if decoded.SchemaVersion != outputSchemaVersion {
		t.Fatalf(
			"schema version = %d; want %d",
			decoded.SchemaVersion,
			outputSchemaVersion,
		)
	}

	if decoded.EventType != "connect_attempt" {
		t.Fatalf(
			"event type = %q; want %q",
			decoded.EventType,
			"connect_attempt",
		)
	}

	wantObservedAt := event.GoTime.UTC().Format(
		"2006-01-02T15:04:05.999999999Z07:00",
	)

	if decoded.ObservedAt != wantObservedAt {
		t.Fatalf(
			"observed_at = %q; want %q",
			decoded.ObservedAt,
			wantObservedAt,
		)
	}

	if decoded.AddressFamily != event.AddressFamily {
		t.Fatalf(
			"address family = %q; want %q",
			decoded.AddressFamily,
			event.AddressFamily,
		)
	}

	if decoded.Process.PID != event.Pid {
		t.Fatalf(
			"PID = %d; want %d",
			decoded.Process.PID,
			event.Pid,
		)
	}

	if decoded.Process.Comm != event.Comm {
		t.Fatalf(
			"comm = %q; want %q",
			decoded.Process.Comm,
			event.Comm,
		)
	}

	if decoded.Process.Executable != event.ProcessPath {
		t.Fatalf(
			"executable = %q; want %q",
			decoded.Process.Executable,
			event.ProcessPath,
		)
	}

	if decoded.Process.User != event.User {
		t.Fatalf(
			"user = %q; want %q",
			decoded.Process.User,
			event.User,
		)
	}

	if decoded.Destination.IP != event.DestIP.String() {
		t.Fatalf(
			"destination IP = %q; want %q",
			decoded.Destination.IP,
			event.DestIP.String(),
		)
	}

	if decoded.Destination.Port != event.DestPort {
		t.Fatalf(
			"destination port = %d; want %d",
			decoded.Destination.Port,
			event.DestPort,
		)
	}
}

func sampleNDJSONEventPayload() eventPayload {
	return eventPayload{
		GoTime: time.Date(
			2026,
			time.July,
			29,
			13,
			45,
			12,
			123456789,
			time.FixedZone("CEST", 2*60*60),
		),
		AddressFamily: "AF_INET",
		Pid:           4242,
		ProcessPath:   "/usr/bin/curl",
		ProcessArgs:   "first line\nsecond line\x1b[31m",
		User:          "alice",
		Comm:          "curl",
		DestIP:        net.ParseIP("203.0.113.10"),
		DestPort:      443,
		ASNameInfo: ASNameInfo{
			AsNumber: 64500,
			Name:     "Example Network",
		},
	}
}
