#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/socket-connect-bpf" >&2
    exit 2
fi

binary="$1"
ipv4_port=18180
ipv6_port=18182
refused_port=18189
output=/tmp/socket-connect-bpf-lifecycle.ndjson
log=/tmp/socket-connect-bpf-lifecycle.log

python3 -m http.server "${ipv4_port}" \
    --bind 127.0.0.1 \
    >/tmp/socket-connect-bpf-lifecycle-http-ipv4.log 2>&1 &
ipv4_server_pid=$!

python3 -m http.server "${ipv6_port}" \
    --bind ::1 \
    >/tmp/socket-connect-bpf-lifecycle-http-ipv6.log 2>&1 &
ipv6_server_pid=$!

cleanup() {
    kill "${ipv4_server_pid}" 2>/dev/null || true
    kill "${ipv6_server_pid}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

sudo timeout \
    --preserve-status \
    --signal=INT \
    10s \
    "${binary}" \
    --tcp-lifecycle \
    --output ndjson \
    >"${output}" \
    2>"${log}" &
tracer_pid=$!

sleep 2

for attempt in 1 2 3; do
    curl \
        --ipv4 \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --header 'Connection: close' \
        "http://127.0.0.1:${ipv4_port}/" \
        >/dev/null

    curl \
        --ipv6 \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --header 'Connection: close' \
        "http://[::1]:${ipv6_port}/" \
        >/dev/null

done

curl \
    --ipv4 \
    --noproxy '*' \
    --connect-timeout 1 \
    --silent \
    --show-error \
    "http://127.0.0.1:${refused_port}/" \
    >/dev/null 2>&1 || true

wait "${tracer_pid}"

python3 - \
    "${output}" \
    "${ipv4_port}" \
    "${ipv6_port}" \
    "${refused_port}" <<'PY'
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
ipv4_port = int(sys.argv[2])
ipv6_port = int(sys.argv[3])
refused_port = int(sys.argv[4])

if not output_path.exists():
    raise SystemExit("TCP lifecycle NDJSON output file was not created")

lines = [
    line
    for line in output_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

if not lines:
    raise SystemExit("TCP lifecycle NDJSON output contained no events")

events = []
for line_number, line in enumerate(lines, start=1):
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"invalid lifecycle JSON on line {line_number}: {error}"
        ) from error

    if event.get("schema_version") != 2:
        raise SystemExit(
            f"unexpected lifecycle schema version on line {line_number}: "
            f"{event.get('schema_version')!r}"
        )

    if event.get("event_type") not in {
        "connect_attempt",
        "tcp_established",
        "tcp_connect_failed",
        "tcp_closed",
    }:
        raise SystemExit(
            f"unexpected lifecycle event type on line {line_number}: "
            f"{event.get('event_type')!r}"
        )

    connection_id = event.get("connection_id")
    if not isinstance(connection_id, int) or connection_id <= 0:
        raise SystemExit(
            f"invalid connection_id on line {line_number}: {connection_id!r}"
        )

    events.append(event)


def matching(remote_ip, remote_port):
    return [
        event
        for event in events
        if event.get("remote", {}).get("ip") == remote_ip
        and event.get("remote", {}).get("port") == remote_port
    ]


def require_success(remote_ip, remote_port, family):
    candidates = matching(remote_ip, remote_port)
    if not candidates:
        raise SystemExit(
            f"no lifecycle events found for {remote_ip}:{remote_port}"
        )

    by_connection = {}
    for event in candidates:
        if event.get("address_family") != family:
            continue
        by_connection.setdefault(event["connection_id"], []).append(event)

    for connection_events in by_connection.values():
        event_types = {
            event["event_type"]
            for event in connection_events
        }
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
            closed = next(
                event
                for event in connection_events
                if event["event_type"] == "tcp_closed"
            )

            if established.get("result") != "success":
                raise SystemExit(
                    f"established event did not report success for "
                    f"{remote_ip}:{remote_port}"
                )

            latency = established.get("connect_latency_ns")
            if not isinstance(latency, int) or latency < 0:
                raise SystemExit(
                    f"invalid connect latency for {remote_ip}:{remote_port}"
                )

            duration = closed.get("connection_duration_ns")
            if not isinstance(duration, int) or duration < 0:
                raise SystemExit(
                    f"invalid connection duration for {remote_ip}:{remote_port}"
                )

            return

    raise SystemExit(
        f"no complete attempt/established/closed lifecycle found for "
        f"{remote_ip}:{remote_port}"
    )


require_success("127.0.0.1", ipv4_port, "AF_INET")
require_success("::1", ipv6_port, "AF_INET6")

failed_candidates = matching("127.0.0.1", refused_port)
if not failed_candidates:
    raise SystemExit("no lifecycle events found for refused connection")

failed_by_connection = {}
for event in failed_candidates:
    failed_by_connection.setdefault(event["connection_id"], []).append(event)

for connection_events in failed_by_connection.values():
    event_types = {event["event_type"] for event in connection_events}
    if {"connect_attempt", "tcp_connect_failed"}.issubset(event_types):
        failed = next(
            event
            for event in connection_events
            if event["event_type"] == "tcp_connect_failed"
        )
        if failed.get("result") != "failed":
            raise SystemExit("failed lifecycle event did not report failed result")
        break
else:
    raise SystemExit("no complete attempt/failure lifecycle found")
PY

if ! grep -Eq \
    'ring-buffer event loss summary: total=[0-9]+' \
    "${log}"
then
    echo "Lifecycle tracer log did not contain an event-loss summary." >&2
    cat "${log}" >&2
    exit 1
fi

if ! grep -Eq \
    'TCP lifecycle diagnostic summary: map_update_failures=[0-9]+ missing_correlation=[0-9]+ unsupported_observations=[0-9]+' \
    "${log}"
then
    echo "Lifecycle tracer log did not contain a diagnostic summary." >&2
    cat "${log}" >&2
    exit 1
fi
