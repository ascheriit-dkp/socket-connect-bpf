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

binary="${1:-./bin/amd64/socket-connect-bpf}"

if [[ ! -x "${binary}" ]]; then
    echo "TCP lifecycle table test binary is not executable: ${binary}" >&2
    exit 1
fi

temporary_directory="$(mktemp -d)"
output="${temporary_directory}/lifecycle-table.txt"
log="${temporary_directory}/lifecycle-table.log"
server_log="${temporary_directory}/server.log"
port=18220
tracer_pid=""
server_pid=""

cleanup() {
    if [[ -n "${tracer_pid}" ]]; then
        kill "${tracer_pid}" 2>/dev/null || true
    fi
    if [[ -n "${server_pid}" ]]; then
        kill "${server_pid}" 2>/dev/null || true
    fi
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

python3 -m http.server "${port}" \
    --bind 127.0.0.1 \
    --directory "${temporary_directory}" \
    >"${server_log}" 2>&1 &
server_pid=$!

sleep 1

sudo timeout \
    --preserve-status \
    --signal=INT \
    7s \
    "${binary}" \
    --tcp-lifecycle \
    --output table \
    >"${output}" \
    2>"${log}" &
tracer_pid=$!

sleep 2

curl \
    --ipv4 \
    --noproxy '*' \
    --fail \
    --silent \
    --show-error \
    --header 'Connection: close' \
    "http://127.0.0.1:${port}/" \
    >/dev/null

if ! wait "${tracer_pid}"; then
    echo "TCP lifecycle table tracer exited unsuccessfully" >&2
    cat "${log}" >&2 || true
    exit 1
fi
tracer_pid=""

if ! grep -Eq '(^|[[:space:]])EVENT([[:space:]]|$)' "${output}"; then
    echo "TCP lifecycle table header is missing EVENT" >&2
    cat "${output}" >&2
    exit 1
fi

for event_type in connect_attempt tcp_established tcp_closed; do
    if ! grep -Fq "${event_type}" "${output}"; then
        echo "TCP lifecycle table output is missing ${event_type}" >&2
        cat "${output}" >&2
        exit 1
    fi
done

if ! grep -Fq "127.0.0.1:${port}" "${output}"; then
    echo "TCP lifecycle table output is missing the remote endpoint" >&2
    cat "${output}" >&2
    exit 1
fi

if ! grep -Eq 'ring-buffer event loss summary: total=[0-9]+' "${log}"; then
    echo "TCP lifecycle table tracer did not report event loss" >&2
    cat "${log}" >&2
    exit 1
fi

if ! grep -Eq 'TCP lifecycle diagnostic summary: map_update_failures=[0-9]+ missing_correlation=[0-9]+ unsupported_observations=[0-9]+' "${log}"; then
    echo "TCP lifecycle table tracer did not report diagnostics" >&2
    cat "${log}" >&2
    exit 1
fi
