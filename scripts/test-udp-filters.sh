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
    echo "UDP filter test binary is not executable: ${binary}" >&2
    exit 1
fi

temporary_directory="$(mktemp -d)"
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

run_tracer() {
    local output_path="$1"
    local log_path="$2"
    shift 2

    sudo timeout \
        --preserve-status \
        --signal=INT \
        7s \
        "${binary}" \
        --udp \
        --output ndjson \
        "$@" \
        >"${output_path}" \
        2>"${log_path}" &

    tracer_pid=$!
    sleep 2

    if ! kill -0 "${tracer_pid}" 2>/dev/null; then
        echo "UDP filter tracer exited before test sends" >&2
        cat "${log_path}" >&2 || true
        wait "${tracer_pid}" || true
        exit 1
    fi
}

wait_for_tracer() {
    local log_path="$1"

    if ! wait "${tracer_pid}"; then
        echo "UDP filter tracer exited unsuccessfully" >&2
        cat "${log_path}" >&2 || true
        exit 1
    fi

    tracer_pid=""

    if ! grep -Eq 'UDP event loss summary: total=[0-9]+' "${log_path}"; then
        echo "UDP filter tracer did not report UDP event loss" >&2
        cat "${log_path}" >&2
        exit 1
    fi

    if ! grep -Eq 'process event loss summary: total=[0-9]+' "${log_path}"; then
        echo "UDP filter tracer did not report process event loss" >&2
        cat "${log_path}" >&2
        exit 1
    fi
}

send_ipv4() {
    local port="$1"

    python3 - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(b"udp-filter-test", ("127.0.0.1", port))
PY
}

send_ipv6() {
    local port="$1"

    python3 - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
try:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
except OSError:
    raise SystemExit(0)

try:
    sock.sendto(b"udp-filter-test-ipv6", ("::1", port))
except OSError:
    pass
finally:
    sock.close()
PY
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

if not path.exists():
    raise SystemExit("filtered UDP output file was not created")

lines = [
    line
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if not lines:
    raise SystemExit("filtered UDP output contained no events")

for line_number, line in enumerate(lines, start=1):
    event = json.loads(line)

    if event.get("schema_version") != 3:
        raise SystemExit(
            f"filtered UDP line {line_number} used schema "
            f"{event.get('schema_version')!r}"
        )
    if event.get("event_type") != "udp_send":
        raise SystemExit(
            f"filtered UDP line {line_number} used event type "
            f"{event.get('event_type')!r}"
        )
    if event.get("protocol") != "udp":
        raise SystemExit(
            f"filtered UDP line {line_number} used protocol "
            f"{event.get('protocol')!r}"
        )
    if event.get("address_family") != expected_family:
        raise SystemExit(
            f"UDP family filter leaked {event.get('address_family')!r}; "
            f"want {expected_family}"
        )

    remote = event.get("remote", {})
    if remote.get("port") != expected_port:
        raise SystemExit(
            f"UDP port filter leaked {remote.get('port')!r}; "
            f"want {expected_port}"
        )

    process = event.get("process", {})
    if expected_pid is not None and process.get("pid") != expected_pid:
        raise SystemExit(
            f"UDP PID filter leaked {process.get('pid')!r}; "
            f"want {expected_pid}"
        )
    if expected_uid is not None and process.get("uid") != expected_uid:
        raise SystemExit(
            f"UDP UID filter leaked {process.get('uid')!r}; "
            f"want {expected_uid}"
        )
PY
}

combined_port=18310
combined_rejected_port=18311
combined_output="${temporary_directory}/combined.ndjson"
combined_log="${temporary_directory}/combined.log"

run_tracer \
    "${combined_output}" \
    "${combined_log}" \
    --family ipv4 \
    --port "${combined_port}"

send_ipv4 "${combined_port}"
send_ipv4 "${combined_rejected_port}"
send_ipv6 "${combined_port}"

wait_for_tracer "${combined_log}"
validate_output \
    "${combined_output}" \
    "${combined_port}" \
    AF_INET \
    "" \
    ""

current_uid="$(id -u)"
uid_port=18312
uid_output="${temporary_directory}/uid.ndjson"
uid_log="${temporary_directory}/uid.log"

run_tracer \
    "${uid_output}" \
    "${uid_log}" \
    --family ipv4 \
    --port "${uid_port}" \
    --uid "${current_uid}"

send_ipv4 "${uid_port}"

if [[ "${current_uid}" -ne 0 ]]; then
    sudo python3 - "${uid_port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(b"udp-filter-root", ("127.0.0.1", port))
PY
fi

wait_for_tracer "${uid_log}"
validate_output \
    "${uid_output}" \
    "${uid_port}" \
    AF_INET \
    "" \
    "${current_uid}"

pid_port=18313
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
        raise SystemExit("PID UDP client gate timed out")
    time.sleep(0.05)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(b"udp-filter-pid", ("127.0.0.1", port))

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
send_ipv4 "${pid_port}"

if ! wait "${pid_client}"; then
    echo "PID UDP client failed" >&2
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

printf '%s\n' "UDP kernel filter integration test passed"
