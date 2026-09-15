#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/socket-connect-bpf" >&2
    exit 2
fi

binary="$1"
ipv4_sendto_port=18280
ipv4_sendmsg_port=18281
ipv6_sendto_port=18282
output=/tmp/socket-connect-bpf-udp.ndjson
log=/tmp/socket-connect-bpf-udp.log
ipv6_marker=/tmp/socket-connect-bpf-udp-ipv6

rm -f "${output}" "${log}" "${ipv6_marker}"

sudo timeout \
    --preserve-status \
    --signal=INT \
    10s \
    "${binary}" \
    --udp \
    --output ndjson \
    >"${output}" \
    2>"${log}" &
tracer_pid=$!

sleep 2

python3 - \
    "${ipv4_sendto_port}" \
    "${ipv4_sendmsg_port}" \
    "${ipv6_sendto_port}" \
    "${ipv6_marker}" <<'PY'
import pathlib
import socket
import sys

sendto_port = int(sys.argv[1])
sendmsg_port = int(sys.argv[2])
ipv6_port = int(sys.argv[3])
ipv6_marker = pathlib.Path(sys.argv[4])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(b"sendto", ("127.0.0.1", sendto_port))
    sock.sendmsg([b"sendmsg"], [], 0, ("127.0.0.1", sendmsg_port))
finally:
    sock.close()

try:
    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock6.sendto(b"ipv6", ("::1", ipv6_port))
    finally:
        sock6.close()
except OSError:
    pass
else:
    ipv6_marker.write_text("1\n", encoding="utf-8")
PY

wait "${tracer_pid}"

python3 - \
    "${output}" \
    "${ipv4_sendto_port}" \
    "${ipv4_sendmsg_port}" \
    "${ipv6_sendto_port}" \
    "${ipv6_marker}" <<'PY'
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
sendto_port = int(sys.argv[2])
sendmsg_port = int(sys.argv[3])
ipv6_port = int(sys.argv[4])
ipv6_marker = pathlib.Path(sys.argv[5])

if not output_path.exists():
    raise SystemExit("UDP NDJSON output file was not created")

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
            f"invalid UDP JSON on line {line_number}: {error}"
        ) from error

    if event.get("schema_version") != 3:
        raise SystemExit(
            f"unexpected UDP schema version on line {line_number}: "
            f"{event.get('schema_version')!r}"
        )
    if event.get("event_type") != "udp_send":
        raise SystemExit(
            f"unexpected UDP event type on line {line_number}: "
            f"{event.get('event_type')!r}"
        )
    if event.get("protocol") != "udp":
        raise SystemExit(
            f"unexpected protocol on line {line_number}: "
            f"{event.get('protocol')!r}"
        )
    if "result" in event or "connection_id" in event:
        raise SystemExit(
            "UDP send event exposed TCP-style result/connection semantics"
        )

    process = event.get("process", {})
    if not isinstance(process.get("pid"), int) or process["pid"] <= 0:
        raise SystemExit("UDP event has no valid process PID")
    if not isinstance(process.get("uid"), int):
        raise SystemExit("UDP event has no valid process UID")
    if not process.get("comm"):
        raise SystemExit("UDP event has no process comm")

    events.append(event)

if not events:
    raise SystemExit("UDP NDJSON output contained no events")


def require_destination(ip, port, family):
    matches = [
        event
        for event in events
        if event.get("address_family") == family
        and event.get("remote", {}).get("ip") == ip
        and event.get("remote", {}).get("port") == port
    ]
    if not matches:
        raise SystemExit(f"no UDP event found for {ip}:{port} ({family})")


require_destination("127.0.0.1", sendto_port, "AF_INET")
require_destination("127.0.0.1", sendmsg_port, "AF_INET")

if ipv6_marker.exists():
    require_destination("::1", ipv6_port, "AF_INET6")

print("UDP visibility integration test passed")
PY

grep -q 'UDP event loss summary: total=0' "${log}"
