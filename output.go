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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

type output interface {
	PrintHeader()
	PrintLine(eventPayload)
}

func newOutput(printAll bool) output {
	return newTableOutput(printAll)
}

type tableOutput struct {
	printAll bool
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

	fmt.Printf(format, args...)
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

		fmt.Printf(
			"%-9s %-9s %-6d %-42s %-16s %-20s %s\n",
			eventTime,
			addressFamily,
			event.Pid,
			process,
			username,
			destination,
			asText,
		)

		return
	}

	fmt.Printf(
		"%-9s %-9s %-6d %-34s %-16s %-20s\n",
		eventTime,
		addressFamily,
		event.Pid,
		processPath,
		username,
		destination,
	)
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
	return &tableOutput{
		printAll: includeASNumbers,
	}
}
