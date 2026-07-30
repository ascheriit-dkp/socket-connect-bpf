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
	"testing"
	"time"
)

func TestNDJSONEventSchemaV1BasicContract(t *testing.T) {
	t.Parallel()

	event := sampleNDJSONEventPayload()
	decoded := encodeSchemaV1Event(t, false, event)

	schemaVersion := decodeRequiredSchemaV1Field[int](
		t,
		decoded,
		"schema_version",
	)

	if schemaVersion != 1 {
		t.Fatalf(
			"schema_version = %d; want 1",
			schemaVersion,
		)
	}

	eventType := decodeRequiredSchemaV1Field[string](
		t,
		decoded,
		"event_type",
	)

	if eventType != "connect_attempt" {
		t.Fatalf(
			"event_type = %q; want %q",
			eventType,
			"connect_attempt",
		)
	}

	observedAt := decodeRequiredSchemaV1Field[string](
		t,
		decoded,
		"observed_at",
	)

	parsedObservedAt, err := time.Parse(time.RFC3339Nano, observedAt)
	if err != nil {
		t.Fatalf(
			"observed_at %q is not RFC 3339 with optional nanoseconds: %v",
			observedAt,
			err,
		)
	}

	_, offset := parsedObservedAt.Zone()
	if offset != 0 {
		t.Fatalf(
			"observed_at offset = %d; want UTC offset 0",
			offset,
		)
	}

	wantObservedAt := event.GoTime.UTC().Format(time.RFC3339Nano)
	if observedAt != wantObservedAt {
		t.Fatalf(
			"observed_at = %q; want %q",
			observedAt,
			wantObservedAt,
		)
	}

	addressFamily := decodeRequiredSchemaV1Field[string](
		t,
		decoded,
		"address_family",
	)

	if addressFamily != event.AddressFamily {
		t.Fatalf(
			"address_family = %q; want %q",
			addressFamily,
			event.AddressFamily,
		)
	}

	process := decodeRequiredSchemaV1Field[map[string]json.RawMessage](
		t,
		decoded,
		"process",
	)

	pid := decodeRequiredSchemaV1Field[uint32](
		t,
		process,
		"pid",
	)

	if pid != event.Pid {
		t.Fatalf(
			"process.pid = %d; want %d",
			pid,
			event.Pid,
		)
	}

	comm := decodeRequiredSchemaV1Field[string](
		t,
		process,
		"comm",
	)

	if comm != event.Comm {
		t.Fatalf(
			"process.comm = %q; want %q",
			comm,
			event.Comm,
		)
	}

	executable := decodeRequiredSchemaV1Field[string](
		t,
		process,
		"executable",
	)

	if executable != event.ProcessPath {
		t.Fatalf(
			"process.executable = %q; want %q",
			executable,
			event.ProcessPath,
		)
	}

	username := decodeRequiredSchemaV1Field[string](
		t,
		process,
		"user",
	)

	if username != event.User {
		t.Fatalf(
			"process.user = %q; want %q",
			username,
			event.User,
		)
	}

	if _, present := process["arguments"]; present {
		t.Fatal(
			"process.arguments is present without extended output",
		)
	}

	destination := decodeRequiredSchemaV1Field[map[string]json.RawMessage](
		t,
		decoded,
		"destination",
	)

	destinationIP := decodeRequiredSchemaV1Field[string](
		t,
		destination,
		"ip",
	)

	if destinationIP != event.DestIP.String() {
		t.Fatalf(
			"destination.ip = %q; want %q",
			destinationIP,
			event.DestIP.String(),
		)
	}

	destinationPort := decodeRequiredSchemaV1Field[uint16](
		t,
		destination,
		"port",
	)

	if destinationPort != event.DestPort {
		t.Fatalf(
			"destination.port = %d; want %d",
			destinationPort,
			event.DestPort,
		)
	}

	if _, present := decoded["asn"]; present {
		t.Fatal("asn is present without extended output")
	}
}

func TestNDJSONEventSchemaV1ExtendedContract(t *testing.T) {
	t.Parallel()

	event := sampleNDJSONEventPayload()
	decoded := encodeSchemaV1Event(t, true, event)

	process := decodeRequiredSchemaV1Field[map[string]json.RawMessage](
		t,
		decoded,
		"process",
	)

	arguments := decodeRequiredSchemaV1Field[string](
		t,
		process,
		"arguments",
	)

	if arguments != event.ProcessArgs {
		t.Fatalf(
			"process.arguments = %q; want %q",
			arguments,
			event.ProcessArgs,
		)
	}

	asn := decodeRequiredSchemaV1Field[map[string]json.RawMessage](
		t,
		decoded,
		"asn",
	)

	asnNumber := decodeRequiredSchemaV1Field[uint32](
		t,
		asn,
		"number",
	)

	if asnNumber != event.ASNameInfo.AsNumber {
		t.Fatalf(
			"asn.number = %d; want %d",
			asnNumber,
			event.ASNameInfo.AsNumber,
		)
	}

	asnName := decodeRequiredSchemaV1Field[string](
		t,
		asn,
		"name",
	)

	if asnName != event.ASNameInfo.Name {
		t.Fatalf(
			"asn.name = %q; want %q",
			asnName,
			event.ASNameInfo.Name,
		)
	}
}

func TestNDJSONEventSchemaV1OmitsUnavailableOptionalFields(
	t *testing.T,
) {
	t.Parallel()

	event := eventPayload{
		GoTime: time.Date(
			2026,
			time.July,
			30,
			12,
			0,
			0,
			0,
			time.UTC,
		),
		AddressFamily: "AF_UNIX",
		Pid:           7,
	}

	decoded := encodeSchemaV1Event(t, true, event)

	process := decodeRequiredSchemaV1Field[map[string]json.RawMessage](
		t,
		decoded,
		"process",
	)

	pid := decodeRequiredSchemaV1Field[uint32](
		t,
		process,
		"pid",
	)

	if pid != event.Pid {
		t.Fatalf(
			"process.pid = %d; want %d",
			pid,
			event.Pid,
		)
	}

	for _, optionalField := range []string{
		"comm",
		"executable",
		"arguments",
		"user",
	} {
		if _, present := process[optionalField]; present {
			t.Fatalf(
				"process.%s is present without data",
				optionalField,
			)
		}
	}

	destination := decodeRequiredSchemaV1Field[map[string]json.RawMessage](
		t,
		decoded,
		"destination",
	)

	if len(destination) != 0 {
		t.Fatalf(
			"destination = %v; want an empty object",
			destination,
		)
	}

	if _, present := decoded["asn"]; present {
		t.Fatal("asn is present without resolved ASN data")
	}
}

func encodeSchemaV1Event(
	t *testing.T,
	includeExtendedFields bool,
	event eventPayload,
) map[string]json.RawMessage {
	t.Helper()

	var buffer bytes.Buffer

	formatter := newNDJSONOutputWithWriter(
		includeExtendedFields,
		&buffer,
	)

	formatter.PrintHeader()
	formatter.PrintLine(event)

	if bytes.Count(buffer.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf(
			"NDJSON output must contain exactly one terminating newline: %q",
			buffer.String(),
		)
	}

	var decoded map[string]json.RawMessage

	if err := json.Unmarshal(
		bytes.TrimSpace(buffer.Bytes()),
		&decoded,
	); err != nil {
		t.Fatalf(
			"decoding schema v1 NDJSON event: %v",
			err,
		)
	}

	for _, requiredField := range []string{
		"schema_version",
		"event_type",
		"observed_at",
		"address_family",
		"process",
		"destination",
	} {
		if _, present := decoded[requiredField]; !present {
			t.Fatalf(
				"required top-level field %q is missing",
				requiredField,
			)
		}
	}

	return decoded
}

func decodeRequiredSchemaV1Field[T any](
	t *testing.T,
	object map[string]json.RawMessage,
	fieldName string,
) T {
	t.Helper()

	var zeroValue T

	rawValue, present := object[fieldName]
	if !present {
		t.Fatalf(
			"required field %q is missing",
			fieldName,
		)

		return zeroValue
	}

	var decoded T

	if err := json.Unmarshal(rawValue, &decoded); err != nil {
		t.Fatalf(
			"field %q has an invalid JSON type or value: %v",
			fieldName,
			err,
		)

		return zeroValue
	}

	return decoded
}
