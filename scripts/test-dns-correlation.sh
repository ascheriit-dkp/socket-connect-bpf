#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/socket-connect-bpf" >&2
    exit 2
fi

binary="$1"
tcp_port=18330
udp_port=18331
server_log=/tmp/socket-connect-bpf-dns-server.log
observation_file=/tmp/socket-connect-bpf-dns-observations.jsonl

rm -f "${server_log}" "${observation_file}"

observed_at="$(date -u -d '30 seconds ago' '+%Y-%m-%dT%H:%M:%SZ')"
cat >"${observation_file}" <<EOF
{"ip":"127.0.0.1","name":"loopback.test","observed_at":"${observed_at}","ttl_seconds":600,"source":"ci-fixture"}
EOF

python3 -m http.server "${tcp_port}" \
    --bind 127.0.0.1 \
    >"${server_log}" 2>&1 &
server_pid=$!

cleanup() {
    kill "${server_pid}" 2>/dev/null || true
    rm -f "${observation_file}"
}
trap cleanup EXIT

sleep 1

run_case() {
    local name="$1"
    local schema="$2"
    local port="$3"
    local transport="$4"
    shift 4

    local output="/tmp/socket-connect-bpf-dns-${name}.ndjson"
    local log="/tmp/socket-connect-bpf-dns-${name}.log"
    rm -f "${output}" "${log}"

    sudo timeout \
        --preserve-status \
        --signal=INT \
        6s \
        "${binary}" \
        --output ndjson \
        --dns-observations "${observation_file}" \
        "$@" \
        >"${output}" \
        2>"${log}" &
    tracer_pid=$!

    sleep 2

    if [[ "${transport}" == "tcp" ]]; then
        python3 - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=2):
    pass
PY
    else
        python3 - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(b"dns-correlation", ("127.0.0.1", port))
finally:
    sock.close()
PY
    fi

    wait "${tracer_pid}"

    python3 - \
        "${output}" \
        "${schema}" \
        "${port}" <<'PY'
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
schema = int(sys.argv[2])
port = int(sys.argv[3])

if not output_path.exists():
    raise SystemExit("DNS correlation NDJSON output file was not created")

matches = []
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
            f"invalid DNS correlation JSON on line {line_number}: {error}"
        ) from error

    if event.get("schema_version") != schema:
        continue

    remote = event.get("remote")
    if not isinstance(remote, dict) or remote.get("port") != port:
        continue

    dns = event.get("dns")
    if not isinstance(dns, dict):
        continue
    if dns.get("name") != "loopback.test":
        continue
    if dns.get("source") != "ci-fixture":
        continue
    if dns.get("confidence") != "medium":
        continue

    matches.append(event)

if not matches:
    raise SystemExit(
        f"no schema v{schema} event for port {port} contained expected DNS metadata"
    )
PY
}

run_case tcp 2 "${tcp_port}" tcp --tcp-lifecycle
run_case udp 3 "${udp_port}" udp --udp

echo "DNS correlation integration test passed."
