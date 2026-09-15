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
	"io"
	"strings"
)

type tcpLifecycleOutput interface {
	PrintHeader() error
	WriteEvent(tcpLifecycleEventPayload) error
}

func newTCPLifecycleOutputForFormat(
	format string,
	writer io.Writer,
) (tcpLifecycleOutput, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", outputFormatTable:
		return newTCPLifecycleTableOutputWithWriter(writer), nil
	case outputFormatNDJSON:
		return newTCPLifecycleNDJSONOutputWithWriter(writer), nil
	default:
		return nil, fmt.Errorf(
			"unsupported output format %q; supported formats are %q and %q",
			format,
			outputFormatTable,
			outputFormatNDJSON,
		)
	}
}

func (output *tcpLifecycleNDJSONOutput) PrintHeader() error {
	return nil
}
