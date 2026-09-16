#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/socket-connect-bpf" >&2
    exit 2
fi

binary="$1"
asn_dir="$(pwd)/as"
tcp_port=18320
udp_port=18321
secret="socket-connect-redaction-secret-72941"
pattern='socket-connect-redaction-secret-[0-9]+'
server_log=/tmp/socket-connect-bpf-redaction-server.log

rm -f "${server_log}"

python3 -m http.server "${tcp_port}" \
    --bind 127.0.0.1 \
    >"${server_log}" 2>&1 &
server_pid=$!

cleanup() {
    kill "${server_pid}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

run_case() {
    local name="$1"
    local schema="$2"
    local port="$3"
    local transport="$4"
    shift 4

    local output="/tmp/socket-connect-bpf-redaction-${name}.ndjson"
    local log="/tmp/socket-connect-bpf-redaction-${name}.log"

    rm -f "${output}" "${log}"

    sudo timeout \
        --preserve-status \
        --signal=INT \
        6s \
        "${binary}" \
        -a \
        --asn-dir "${asn_dir}" \
        --output ndjson \
        --redact-arg "${pattern}" \
        "$@" \
        >"${output}" \
        2>"${log}" &
    tracer_pid=$!

    sleep 2

    if [[ "${transport}" == "tcp" ]]; then
        python3 - "${port}" "${secret}" <<'PY' &
import socket
import sys
import time

port = int(sys.argv[1])
secret = sys.argv[2]
with socket.create_connection(("127.0.0.1", port), timeout=2):
    time.sleep(1.5)
assert secret
PY
    else
        python3 - "${port}" "${secret}" <<'PY' &
import socket
import sys
import time

port = int(sys.argv[1])
secret = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(b"redaction", ("127.0.0.1", port))
    time.sleep(1.5)
finally:
    sock.close()
assert secret
PY
    fi
    client_pid=$!

    wait "${client_pid}"
    wait "${tracer_pid}"

    if grep -Fq "${secret}" "${output}"; then
        echo "${name}: raw secret leaked into tracer output" >&2
        cat "${output}" >&2
        exit 1
    fi

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
    raise SystemExit("redaction NDJSON output file was not created")

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
            f"invalid redaction JSON on line {line_number}: {error}"
        ) from error

    if event.get("schema_version") != schema:
        continue

    endpoint = event.get("destination") if schema == 1 else event.get("remote")
    if not isinstance(endpoint, dict) or endpoint.get("port") != port:
        continue

    arguments = event.get("process", {}).get("arguments", "")
    if "[REDACTED]" in arguments:
        matches.append(event)

if not matches:
    raise SystemExit(
        f"no schema v{schema} event for port {port} contained redacted arguments"
    )
PY
}

run_case legacy 1 "${tcp_port}" tcp
run_case tcp 2 "${tcp_port}" tcp --tcp-lifecycle
run_case udp 3 "${udp_port}" udp --udp

echo "Argument redaction integration test passed."
