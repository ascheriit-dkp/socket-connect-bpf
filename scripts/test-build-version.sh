#!/usr/bin/env bash
#
# Copyright 2026 Ascheriit-Dkp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 BINARY VERSION COMMIT BUILD_DATE" >&2
    exit 2
fi

binary="$1"
version="$2"
commit="$3"
build_date="$4"

expected="socket-connect-bpf ${version} commit=${commit} built=${build_date}"
actual="$(${binary} --version)"

if [[ "${actual}" != "${expected}" ]]; then
    echo "binary version metadata mismatch" >&2
    echo "expected: ${expected}" >&2
    echo "actual:   ${actual}" >&2
    exit 1
fi

echo "Binary version metadata passed."
