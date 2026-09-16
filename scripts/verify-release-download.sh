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
    echo \
        "usage: $0 ASSET_DIR VERSION COMMIT BUILD_DATE" \
        >&2
    exit 2
fi

asset_directory="$1"
expected_version="$2"
expected_commit="$3"
expected_build_date="$4"

for command in python3 sha256sum tar mktemp; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required command not found: ${command}" >&2
        exit 1
    fi
done

expected_files=(
    "SHA256SUMS"
    "socket-connect-bpf-linux-amd64.tar.gz"
    "socket-connect-bpf-linux-arm64.tar.gz"
    "socket-connect-bpf-linux-amd64.spdx.json"
    "socket-connect-bpf-linux-arm64.spdx.json"
)

for filename in "${expected_files[@]}"; do
    if [[ ! -f "${asset_directory}/${filename}" ]]; then
        echo "release asset not found: ${asset_directory}/${filename}" >&2
        exit 1
    fi
done

(
    cd "${asset_directory}"
    sha256sum --check --strict SHA256SUMS
)

python3 - \
    "${asset_directory}/socket-connect-bpf-linux-amd64.spdx.json" \
    "${asset_directory}/socket-connect-bpf-linux-arm64.spdx.json" <<'PY'
import json
import pathlib
import sys

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid SPDX JSON {path}: {error}") from error

    if not isinstance(document, dict):
        raise SystemExit(f"SPDX document is not an object: {path}")
    if not str(document.get("spdxVersion", "")).startswith("SPDX-"):
        raise SystemExit(f"SPDX version missing from {path}")
PY

temporary_directory="$(mktemp -d)"
cleanup() {
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

tar \
    -xzf "${asset_directory}/socket-connect-bpf-linux-amd64.tar.gz" \
    -C "${temporary_directory}"

binary="${temporary_directory}/socket-connect-bpf"
if [[ ! -x "${binary}" ]]; then
    echo "packaged amd64 binary is missing or not executable" >&2
    exit 1
fi

actual_version="$(${binary} --version)"
expected_output="socket-connect-bpf ${expected_version} commit=${expected_commit} built=${expected_build_date}"

if [[ "${actual_version}" != "${expected_output}" ]]; then
    echo "packaged version metadata mismatch" >&2
    echo "expected: ${expected_output}" >&2
    echo "actual:   ${actual_version}" >&2
    exit 1
fi

echo "Downloaded release assets verified successfully."
