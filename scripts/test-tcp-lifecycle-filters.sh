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
    echo "TCP lifecycle filter test binary is not executable: ${binary}" >&2
    exit 1
fi

temporary_directory="$(mktemp -d)"
server_directory="${temporary_directory}/server"
mkdir -p "${server_directory}"

combined_port=18210
combined_rejected_port=18211
combined_ipv6_port=18212
uid_port=18213
pid_port=18214

tracer_pid=""
declare -a background_pids=()

cleanup() {
    if [[ -n "${tracer_pid}" ]]; then
        kill "${tracer_pid}" 2>/dev/null || true
    fi

    for background_pid in "${background_pids[@]}"; do
        kill "${background_pid}" 2>/dev/null || true
    done

    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

start_http_server() {
    local bind_address="$1"
    local port="$2"
    local log_path="$3"

    python3 -m http.server "${port}" \
        --bind "${bind_address}" \
        --directory "${server_directory}" \
        >"${log_path}" 2>&1 &

    background_pids+=("$!")
}

start_http_server \
    127.0.0.1 \
    "${combined_port}" \
    "${temporary_directory}/combined-match-server.log"
start_http_server \
    127.0.0.1 \
    "${combined_rejected_port}" \
    "${temporary_directory}/combined-rejected-server.log"
start_http_server \
    ::1 \
    "${combined_ipv6_port}" \
    "${temporary_directory}/combined-ipv6-server.log"
start_http_server \
    127.0.0.1 \
    "${uid_port}" \
    "${temporary_directory}/uid-server.log"
start_http_server \
    127.0.0.1 \
    "${pid_port}" \
    "${temporary_directory}/pid-server.log"

sleep 1

for server_pid in "${background_pids[@]}"; do
    if ! kill -0 "${server_pid}" 2>/dev/null; then
        echo "TCP lifecycle filter HTTP server exited during startup" >&2
        exit 1
    fi
done

run_tracer() {
    local output_path="$1"
    local log_path="$2"
    shift 2

    sudo timeout \
        --preserve-status \
        --signal=INT \
        7s \
        "${binary}" \
        --tcp-lifecycle \
        --output ndjson \
        "$@" \
        >"${output_path}" \
        2>"${log_path}" &

    tracer_pid=$!
    sleep 2

    if ! kill -0 "${tracer_pid}" 2>/dev/null; then
        echo "TCP lifecycle filter tracer exited before requests" >&2
        cat "${log_path}" >&2 || true
        wait "${tracer_pid}" || true
        exit 1
    fi
}

wait_for_tracer() {
    local log_path="$1"

    if ! wait "${tracer_pid}"; then
        echo "TCP lifecycle filter tracer exited unsuccessfully" >&2
        cat "${log_path}" >&2 || true
        exit 1
    fi

    tracer_pid=""

    if ! grep -Eq \
        'ring-buffer event loss summary: total=[0-9]+' \
        "${log_path}"
    then
        echo "TCP lifecycle filter tracer did not report event loss" >&2
        cat "${log_path}" >&2
        exit 1
    fi

    if ! grep -Eq \
        'TCP lifecycle diagnostic summary: map_update_failures=[0-9]+ missing_correlation=[0-9]+ unsupported_observations=[0-9]+' \
        "${log_path}"
    then
        echo "TCP lifecycle filter tracer did not report diagnostics" >&2
        cat "${log_path}" >&2
        exit 1
    fi
}

curl_ipv4() {
    local port="$1"

    curl \
        --ipv4 \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --header 'Connection: close' \
        "http://127.0.0.1:${port}/" \
        >/dev/null
}

curl_ipv6() {
    local port="$1"

    curl \
        --ipv6 \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --header 'Connection: close' \
        "http://[::1]:${port}/" \
        >/dev/null
}

validate_output() {
    local output_path="$1"
    local expected_port="$2"
    local expected_family="$3"
    local expected_pid="$4"
    local expected_uid="$5"

    python3 - \
        "${output_path}" \
        "${expected_port}" \
        "${expected_family}" \
        "${expected_pid}" \
        "${expected_uid}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_port = int(sys.argv[2])
expected_family = sys.argv[3]
expected_pid = int(sys.argv[4]) if sys.argv[4] else None
expected_uid = int(sys.argv[5]) if sys.argv[5] else None

lines = [
    line
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if not lines:
    raise SystemExit("filtered lifecycle output contained no events")

events = [json.loads(line) for line in lines]

for event in events:
    if event.get("schema_version") != 2:
        raise SystemExit("filtered lifecycle output used the wrong schema")

    if event.get("address_family") != expected_family:
        raise SystemExit(
            f"unexpected address family: {event.get('address_family')!r}"
        )

    remote = event.get("remote", {})
    if remote.get("port") != expected_port:
        raise SystemExit(
            f"filter leaked remote port {remote.get('port')!r}; "
            f"want {expected_port}"
        )

    process = event.get("process", {})
    if expected_pid is not None and process.get("pid") != expected_pid:
        raise SystemExit(
            f"filter leaked PID {process.get('pid')!r}; want {expected_pid}"
        )
    if expected_uid is not None and process.get("uid") != expected_uid:
        raise SystemExit(
            f"filter leaked UID {process.get('uid')!r}; want {expected_uid}"
        )

by_connection = {}
for event in events:
    by_connection.setdefault(event["connection_id"], []).append(event)

for connection_events in by_connection.values():
    event_types = {event["event_type"] for event in connection_events}
    if {
        "connect_attempt",
        "tcp_established",
        "tcp_closed",
    }.issubset(event_types):
        break
else:
    raise SystemExit(
        "filtered lifecycle output contained no complete "
        "attempt/established/closed lifecycle"
    )
PY
}

combined_output="${temporary_directory}/combined.ndjson"
combined_log="${temporary_directory}/combined.log"

run_tracer \
    "${combined_output}" \
    "${combined_log}" \
    --family ipv4 \
    --port "${combined_port}"

curl_ipv4 "${combined_port}"
curl_ipv4 "${combined_rejected_port}"
curl_ipv6 "${combined_ipv6_port}"

wait_for_tracer "${combined_log}"
validate_output \
    "${combined_output}" \
    "${combined_port}" \
    AF_INET \
    "" \
    ""

current_uid="$(id -u)"
uid_output="${temporary_directory}/uid.ndjson"
uid_log="${temporary_directory}/uid.log"

run_tracer \
    "${uid_output}" \
    "${uid_log}" \
    --family ipv4 \
    --port "${uid_port}" \
    --uid "${current_uid}"

curl_ipv4 "${uid_port}"

if [[ "${current_uid}" -ne 0 ]]; then
    sudo curl \
        --ipv4 \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --header 'Connection: close' \
        "http://127.0.0.1:${uid_port}/" \
        >/dev/null
fi

wait_for_tracer "${uid_log}"
validate_output \
    "${uid_output}" \
    "${uid_port}" \
    AF_INET \
    "" \
    "${current_uid}"

pid_gate="${temporary_directory}/pid-go"
pid_client_log="${temporary_directory}/pid-client.log"

python3 - \
    "${pid_gate}" \
    "${pid_port}" \
    >"${pid_client_log}" 2>&1 <<'PY' &
import pathlib
import socket
import sys
import time

gate = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])

deadline = time.monotonic() + 6
while not gate.exists():
    if time.monotonic() >= deadline:
        raise SystemExit("PID lifecycle client gate timed out")
    time.sleep(0.05)

with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
    sock.sendall(
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: close\r\n\r\n"
    )
    while sock.recv(4096):
        pass

time.sleep(0.5)
PY
pid_client=$!
background_pids+=("${pid_client}")

pid_output="${temporary_directory}/pid.ndjson"
pid_log="${temporary_directory}/pid.log"

run_tracer \
    "${pid_output}" \
    "${pid_log}" \
    --family ipv4 \
    --port "${pid_port}" \
    --pid "${pid_client}"

touch "${pid_gate}"
curl_ipv4 "${pid_port}"

if ! wait "${pid_client}"; then
    echo "PID lifecycle client failed" >&2
    cat "${pid_client_log}" >&2 || true
    exit 1
fi

wait_for_tracer "${pid_log}"
validate_output \
    "${pid_output}" \
    "${pid_port}" \
    AF_INET \
    "${pid_client}" \
    ""
