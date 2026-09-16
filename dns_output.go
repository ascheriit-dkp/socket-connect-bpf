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

import "time"

type dnsCorrelationNDJSON struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	ObservedAt string `json:"observed_at"`
	ExpiresAt  string `json:"expires_at"`
}

func newDNSCorrelationNDJSON(
	value *dnsCorrelationPayload,
) *dnsCorrelationNDJSON {
	if value == nil {
		return nil
	}

	return &dnsCorrelationNDJSON{
		Name:       value.Name,
		Source:     value.Source,
		Confidence: value.Confidence,
		ObservedAt: value.ObservedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:  value.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

func formatDNSCorrelationTable(value *dnsCorrelationPayload) string {
	if value == nil {
		return "-"
	}

	return sanitizeTerminalField(
		value.Name + " (" + value.Confidence + ", " + value.Source + ")",
	)
}
