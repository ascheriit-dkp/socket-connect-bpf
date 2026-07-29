// Copyright 2019 Peter Stöckli
// Modified in 2026 by Ascheriit-Dkp.
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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

const (
	outputFormatTable  = "table"
	outputFormatNDJSON = "ndjson"

	outputSchemaVersion = 1
)

type output interface {
	PrintHeader()
	PrintLine(eventPayload)
}

// newOutput preserves the original table-output constructor.
//
// New callers should use newOutputForFormat so that the requested output
// format can be validated.
func newOutput(printAll bool) output {
	return newTableOutputWithWriter(printAll, os.Stdout)
}

func newOutputForFormat(format string, printAll bool) (output, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", outputFormatTable:
		return newTableOutputWithWriter(printAll, os.Stdout), nil
	case outputFormatNDJSON:
		return newNDJSONOutputWithWriter(printAll, os.Stdout), nil
	default:
		return nil, fmt.Errorf(
			"unsupported output format %q; supported formats are %q and %q",
			format,
			outputFormatTable,
			outputFormatNDJSON,
		)
	}
}

type tableOutput struct {
	printAll bool
	writer   io.Writer
	mu       sync.Mutex
}

func (t *tableOutput) PrintHeader() {
	t.mu.Lock()
	defer t.mu.Unlock()

	var format string
	var args []interface{}

	if t.printAll {
		format = "%-9s %-9s %-6s %-42s %-16s %-20s %s\n"
		args = []interface{}{
			"TIME",
			"AF",
			"PID",
			"PROCESS",
			"USER",
			"DESTINATION",
			"AS-INFO",
		}
	} else {
		format = "%-9s %-9s %-6s %-34s %-16s %-20s\n"
		args = []interface{}{
			"TIME",
			"AF",
			"PID",
			"PROCESS",
			"USER",
			"DESTINATION",
		}
	}

	if _, err := fmt.Fprintf(t.writer, format, args...); err != nil {
		log.Printf("writing table header: %s", err)
	}
}

func (t *tableOutput) PrintLine(event eventPayload) {
	t.mu.Lock()
	defer t.mu.Unlock()

	eventTime := event.GoTime.Format("15:04:05")
	addressFamily := sanitizeTerminalField(event.AddressFamily)
	destination := event.DestIP.String() + " " +
		strconv.Itoa(int(event.DestPort))
	processPath := sanitizeTerminalField(event.ProcessPath)
	processArgs := sanitizeTerminalField(event.ProcessArgs)
	username := sanitizeTerminalField(event.User)

	if t.printAll {
		process := processPath
		if processArgs != "" {
			process += " " + processArgs
		}

		asText := ""
		if event.ASNameInfo != (ASNameInfo{}) {
			asText = "AS" +
				strconv.Itoa(int(event.ASNameInfo.AsNumber)) +
				" (" +
				sanitizeTerminalField(event.ASNameInfo.Name) +
				")"
		}

		if _, err := fmt.Fprintf(
			t.writer,
			"%-9s %-9s %-6d %-42s %-16s %-20s %s\n",
			eventTime,
			addressFamily,
			event.Pid,
			process,
			username,
			destination,
			asText,
		); err != nil {
			log.Printf("writing table event: %s", err)
		}

		return
	}

	if _, err := fmt.Fprintf(
		t.writer,
		"%-9s %-9s %-6d %-34s %-16s %-20s\n",
		eventTime,
		addressFamily,
		event.Pid,
		processPath,
		username,
		destination,
	); err != nil {
		log.Printf("writing table event: %s", err)
	}
}

type ndjsonOutput struct {
	includeExtendedFields bool
	encoder               *json.Encoder
	mu                    sync.Mutex
}

type ndjsonEvent struct {
	SchemaVersion int               `json:"schema_version"`
	EventType     string            `json:"event_type"`
	ObservedAt    string            `json:"observed_at"`
	AddressFamily string            `json:"address_family"`
	Process       ndjsonProcess      `json:"process"`
	Destination   ndjsonDestination  `json:"destination"`
	ASN           *ndjsonASN         `json:"asn,omitempty"`
}

type ndjsonProcess struct {
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm,omitempty"`
	Executable string `json:"executable,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	User       string `json:"user,omitempty"`
}

type ndjsonDestination struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

type ndjsonASN struct {
	Number uint32 `json:"number"`
	Name   string `json:"name,omitempty"`
}

func (n *ndjsonOutput) PrintHeader() {
	// NDJSON is a stream of independent JSON objects and therefore has no
	// human-readable header.
}

func (n *ndjsonOutput) PrintLine(event eventPayload) {
	n.mu.Lock()
	defer n.mu.Unlock()

	jsonEvent := ndjsonEvent{
		SchemaVersion: outputSchemaVersion,
		EventType:     "connect_attempt",
		ObservedAt:    event.GoTime.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		AddressFamily: event.AddressFamily,
		Process: ndjsonProcess{
			PID:        event.Pid,
			Comm:       event.Comm,
			Executable: event.ProcessPath,
			User:       event.User,
		},
		Destination: ndjsonDestination{
			Port: event.DestPort,
		},
	}

	if event.DestIP != nil {
		jsonEvent.Destination.IP = event.DestIP.String()
	}

	if n.includeExtendedFields {
		jsonEvent.Process.Arguments = event.ProcessArgs

		if event.ASNameInfo != (ASNameInfo{}) {
			jsonEvent.ASN = &ndjsonASN{
				Number: event.ASNameInfo.AsNumber,
				Name:   event.ASNameInfo.Name,
			}
		}
	}

	if err := n.encoder.Encode(jsonEvent); err != nil {
		log.Printf("writing NDJSON event: %s", err)
	}
}

// sanitizeTerminalField makes untrusted text safe to print to a terminal.
//
// Control characters, newlines, tabs, escape sequences and invisible Unicode
// formatting characters are rendered as visible escape sequences.
func sanitizeTerminalField(value string) string {
	var builder strings.Builder

	for _, character := range value {
		switch character {
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		case '\\':
			builder.WriteString(`\\`)
		default:
			if unicode.IsGraphic(character) {
				builder.WriteRune(character)
				continue
			}

			if character <= '\uFFFF' {
				fmt.Fprintf(&builder, `\u%04X`, character)
			} else {
				fmt.Fprintf(&builder, `\U%08X`, character)
			}
		}
	}

	return builder.String()
}

func newTableOutput(includeASNumbers bool) output {
	return newTableOutputWithWriter(includeASNumbers, os.Stdout)
}

func newTableOutputWithWriter(
	includeASNumbers bool,
	writer io.Writer,
) output {
	return &tableOutput{
		printAll: includeASNumbers,
		writer:   writer,
	}
}

func newNDJSONOutputWithWriter(
	includeExtendedFields bool,
	writer io.Writer,
) output {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)

	return &ndjsonOutput{
		includeExtendedFields: includeExtendedFields,
		encoder:               encoder,
	}
}
