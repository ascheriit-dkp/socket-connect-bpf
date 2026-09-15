#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/socket-connect-bpf" >&2
    exit 2
fi

binary="$1"
port=18210
output=/tmp/socket-connect-bpf-process-context.ndjson
log=/tmp/socket-connect-bpf-process-context.log
server_log=/tmp/socket-connect-bpf-process-context-server.log

rm -f "${output}" "${log}" "${server_log}"

python3 -m http.server "${port}" \
    --bind 127.0.0.1 \
    >"${server_log}" 2>&1 &
server_pid=$!

cleanup() {
    kill "${server_pid}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

sudo timeout \
    --preserve-status \
    --signal=INT \
    8s \
    "${binary}" \
    --tcp-lifecycle \
    --output ndjson \
    >"${output}" \
    2>"${log}" &
tracer_pid=$!

sleep 2

python3 - "${port}" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
time.sleep(0.5)
with socket.create_connection(("127.0.0.1", port), timeout=2):
    pass
PY

wait "${tracer_pid}"

python3 - "${output}" "${port}" <<'PY'
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])

if not output_path.exists():
    raise SystemExit("process-context NDJSON output file was not created")

events = []
for line_number, line in enumerate(
    output_path.read_text(encoding="utf-8").splitlines(),
    start=1,
):
    if not line.strip():
        continue
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"invalid process-context JSON on line {line_number}: {error}"
        ) from error

    if event.get("remote", {}).get("port") == port:
        events.append(event)

if not events:
    raise SystemExit("no lifecycle events found for process-context test")

by_connection = {}
for event in events:
    by_connection.setdefault(event.get("connection_id"), []).append(event)

selected = None
for connection_id, connection_events in by_connection.items():
    types = {event.get("event_type") for event in connection_events}
    if "connect_attempt" in types and "tcp_established" in types:
        selected = (connection_id, connection_events)
        break

if selected is None:
    raise SystemExit("no established process-context connection was observed")

connection_id, connection_events = selected
attempt = next(
    event
    for event in connection_events
    if event.get("event_type") == "connect_attempt"
)
process = attempt.get("process")
if not isinstance(process, dict):
    raise SystemExit("connect attempt has no process object")

if not isinstance(process.get("gid"), int) or process["gid"] < 0:
    raise SystemExit(f"invalid process gid: {process.get('gid')!r}")

if not isinstance(process.get("start_time_ticks"), int) or process["start_time_ticks"] <= 0:
    raise SystemExit(
        f"invalid process start identity: {process.get('start_time_ticks')!r}"
    )

parent = process.get("parent")
if not isinstance(parent, dict) or not isinstance(parent.get("pid"), int):
    raise SystemExit(f"invalid parent process context: {parent!r}")

cgroup = process.get("cgroup")
if not isinstance(cgroup, dict):
    raise SystemExit("process cgroup context is missing")
if not (
    isinstance(cgroup.get("id"), int) and cgroup["id"] > 0
) and not (
    isinstance(cgroup.get("path"), str) and cgroup["path"].startswith("/")
):
    raise SystemExit(f"invalid cgroup context: {cgroup!r}")

namespaces = process.get("namespaces")
if not isinstance(namespaces, dict):
    raise SystemExit("process namespace context is missing")
for name in ("mnt", "net", "pid"):
    if not isinstance(namespaces.get(name), int) or namespaces[name] <= 0:
        raise SystemExit(
            f"invalid {name} namespace ID: {namespaces.get(name)!r}"
        )

if not process.get("executable"):
    raise SystemExit("process executable was not preserved")

stable_fields = (
    "pid",
    "uid",
    "gid",
    "comm",
    "executable",
    "user",
    "start_time_ticks",
    "parent",
    "cgroup",
    "namespaces",
    "container",
)

for event in connection_events:
    current = event.get("process", {})
    for field in stable_fields:
        if current.get(field) != process.get(field):
            raise SystemExit(
                f"connection {connection_id} changed process field {field}: "
                f"{process.get(field)!r} -> {current.get(field)!r}"
            )

print("Process context lifecycle test passed.")
PY

grep -q 'process event loss summary: total=0' "${log}"
