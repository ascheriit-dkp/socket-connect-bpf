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
	"encoding/binary"
	"fmt"
)

// decodeKernelTCPLifecycleEvent decodes and validates one fixed-size internal
// TCP lifecycle record received from the shared kernel ring buffer.
//
// Public output is intentionally not produced here. Decoding, validation and
// output conversion remain separate so malformed kernel records cannot reach
// an output encoder.
func decodeKernelTCPLifecycleEvent(
	rawSample []byte,
) (kernelTCPLifecycleEvent, error) {
	var event kernelTCPLifecycleEvent

	if len(rawSample) != kernelTCPLifecycleEventBinarySize {
		return event, fmt.Errorf(
			"unexpected TCP lifecycle record size %d; want %d",
			len(rawSample),
			kernelTCPLifecycleEventBinarySize,
		)
	}

	if err := binary.Read(
		bytes.NewReader(rawSample),
		binary.LittleEndian,
		&event,
	); err != nil {
		return kernelTCPLifecycleEvent{}, fmt.Errorf(
			"decode TCP lifecycle kernel event: %w",
			err,
		)
	}

	if err := validateKernelTCPLifecycleEvent(event); err != nil {
		return kernelTCPLifecycleEvent{}, fmt.Errorf(
			"validate TCP lifecycle kernel event: %w",
			err,
		)
	}

	return event, nil
}
