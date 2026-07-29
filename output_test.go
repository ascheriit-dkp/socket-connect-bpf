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

import "testing"

func TestSanitizeTerminalField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain ASCII",
			input: "curl --silent example.com",
			want:  "curl --silent example.com",
		},
		{
			name:  "printable Unicode",
			input: "héllo 世界 🚀",
			want:  "héllo 世界 🚀",
		},
		{
			name:  "newline",
			input: "first\nsecond",
			want:  `first\nsecond`,
		},
		{
			name:  "carriage return",
			input: "first\rsecond",
			want:  `first\rsecond`,
		},
		{
			name:  "tab",
			input: "first\tsecond",
			want:  `first\tsecond`,
		},
		{
			name:  "backslash",
			input: `C:\temporary\file`,
			want:  `C:\\temporary\\file`,
		},
		{
			name:  "ANSI color escape sequence",
			input: "\x1b[31mred\x1b[0m",
			want:  `\u001B[31mred\u001B[0m`,
		},
		{
			name:  "null byte",
			input: "before\x00after",
			want:  `before\u0000after`,
		},
		{
			name:  "zero width joiner",
			input: "before\u200Dafter",
			want:  `before\u200Dafter`,
		},
		{
			name:  "supplementary private-use character",
			input: "before\U000F0000after",
			want:  `before\U000F0000after`,
		},
		{
			name:  "empty value",
			input: "",
			want:  "",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := sanitizeTerminalField(test.input)
			if got != test.want {
				t.Fatalf(
					"sanitizeTerminalField(%q) = %q; want %q",
					test.input,
					got,
					test.want,
				)
			}
		})
	}
}

func TestSanitizeTerminalFieldContainsNoRawControlCharacters(t *testing.T) {
	t.Parallel()

	input := "start\x00\x01\x02\n\r\t\x1bend"
	got := sanitizeTerminalField(input)

	for _, character := range got {
		if character < 0x20 || character == 0x7F {
			t.Fatalf(
				"sanitized output still contains control character U+%04X: %q",
				character,
				got,
			)
		}
	}
}
