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
	"strings"
	"testing"
)

func TestValidateKernelTCPLifecycleEventAllowsPresentZeroPorts(
	t *testing.T,
) {
	t.Parallel()

	event := validIPv4TCPLifecycleAttempt()
	event.LocalPort = 0
	event.RemotePort = 0

	if err := validateKernelTCPLifecycleEvent(event); err != nil {
		t.Fatalf("validating zero-valued present ports: %v", err)
	}
}

func TestValidateKernelTCPLifecycleEventRejectsClosedBeforeAttempt(
	t *testing.T,
) {
	t.Parallel()

	event := validIPv4TCPLifecycleAttempt()
	event.EventType = kernelTCPLifecycleEventTypeClosed
	event.KernelTimestampNS = 3_000
	event.EstablishedTimestampNS = event.AttemptTimestampNS - 1

	err := validateKernelTCPLifecycleEvent(event)
	if err == nil {
		t.Fatal("validation succeeded; want an error")
	}

	if !strings.Contains(err.Error(), "before attempt timestamp") {
		t.Fatalf(
			"error = %q; want timeline-ordering detail",
			err,
		)
	}
}
