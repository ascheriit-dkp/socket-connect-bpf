// Copyright 2026 Ascheriit-Dkp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except6 Ascheriit-Dkp.
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
	"time"
)

// decodeTCPLifecycleEventPayload converts one raw internal ABI v2 lifecycle
// record into its validated userspace representation.
//
// observedAt is supplied by the caller so wall-clock observation remains
// separate from the monotonic kernel timestamps contained in the record.
func decodeTCPLifecycleEventPayload(
	rawSample []byte,
	observedAt time.Time,
) (tcpLifecycleEventPayload, error) {
	event, err := decodeKernelTCPLifecycleEvent(rawSample)
	if err != nil {
		return tcpLifecycleEventPayload{}, fmt.Errorf(
			"decode TCP lifecycle record: %w",
			err,
		)
	}

	payload, err := newTCPLifecycleEventPayload(event, observedAt)
	if err != nil {
		return tcpLifecycleEventPayload{}, fmt.Errorf(
			"convert TCP lifecycle record: %w",
			err,
		)
	}

	return payload, nil
}
