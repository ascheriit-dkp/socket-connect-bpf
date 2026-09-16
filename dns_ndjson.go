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
	"encoding/json"
	"net"
)

type dnsNDJSONPayload struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

func (event tcpLifecycleNDJSONEvent) MarshalJSON() ([]byte, error) {
	type eventAlias tcpLifecycleNDJSONEvent

	return json.Marshal(struct {
		eventAlias
		DNS *dnsNDJSONPayload `json:"dns,omitempty"`
	}{
		eventAlias: eventAlias(event),
		DNS:        dnsNDJSONForRemote(event.Remote.IP),
	})
}

func (event udpNDJSONEvent) MarshalJSON() ([]byte, error) {
	type eventAlias udpNDJSONEvent

	return json.Marshal(struct {
		eventAlias
		DNS *dnsNDJSONPayload `json:"dns,omitempty"`
	}{
		eventAlias: eventAlias(event),
		DNS:        dnsNDJSONForRemote(event.Remote.IP),
	})
}

func dnsNDJSONForRemote(remoteIP string) *dnsNDJSONPayload {
	if !dnsEnrichmentEnabled() || remoteIP == "" {
		return nil
	}

	correlation := lookupDNSCorrelation(net.ParseIP(remoteIP))
	if correlation == nil {
		return nil
	}

	return &dnsNDJSONPayload{
		Name:       correlation.Name,
		Source:     correlation.Source,
		Confidence: correlation.Confidence,
	}
}
