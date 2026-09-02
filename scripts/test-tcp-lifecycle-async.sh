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
    echo "TCP lifecycle async test binary is not executable: ${binary}" >&2
    exit 1
fi

temporary_directory="$(mktemp -d)"
output="${temporary_directory}/async.ndjson"
log="${temporary_directory}/async.log"
server_log="${temporary_directory}/server.log"
port=18230
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
    --output ndjson \
    --family ipv4 \
    --port "${port}" \
    >"${output}" \
    2>"${log}" &
tracer_pid=$!

sleep 2

python3 - "${port}" <<'PY'
import errno
import select
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(False)

try:
    result = sock.connect_ex(("127.0.0.1", port))
    allowed = {
        0,
        errno.EINPROGRESS,
        errno.EALREADY,
        errno.EWOULDBLOCK,
    }
    if result not in allowed:
        raise SystemExit(f"unexpected non-blocking connect result: {result}")

    if result != 0:
        _, writable, exceptional = select.select([], [sock], [sock], 3)
        if exceptional or not writable:
            raise SystemExit("non-blocking connect did not become writable")

        socket_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if socket_error != 0:
            raise SystemExit(
                f"non-blocking connect completed with errno {socket_error}"
            )

    sock.setblocking(True)
    sock.sendall(
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: close\r\n\r\n"
    )
    while sock.recv(4096):
        pass
finally:
    sock.close()
PY

if ! wait "${tracer_pid}"; then
    echo "TCP lifecycle async tracer exited unsuccessfully" >&2
    cat "${log}" >&2 || true
    exit 1
fi
tracer_pid=""

python3 - "${output}" "${port}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])

events = [
    json.loads(line)
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

candidates = [
    event
    for event in events
    if event.get("remote", {}).get("ip") == "127.0.0.1"
    and event.get("remote", {}).get("port") == port
]

by_connection = {}
for event in candidates:
    by_connection.setdefault(event["connection_id"], []).append(event)

for connection_events in by_connection.values():
    event_types = {event["event_type"] for event in connection_events}
    if {
        "connect_attempt",
        "tcp_established",
        "tcp_closed",
    }.issubset(event_types):
        established = next(
            event
            for event in connection_events
            if event["event_type"] == "tcp_established"
        )
        if established.get("result") != "success":
            raise SystemExit("async established event did not report success")
        latency = established.get("connect_latency_ns")
        if not isinstance(latency, int) or latency < 0:
            raise SystemExit("async established event has invalid latency")
        break
else:
    raise SystemExit(
        "no complete lifecycle was observed for the non-blocking connect"
    )
PY
