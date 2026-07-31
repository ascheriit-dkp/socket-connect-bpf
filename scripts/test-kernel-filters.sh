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
	echo "kernel-filter integration binary is not executable: ${binary}" >&2
	exit 1
fi

temporary_directory="$(mktemp -d)"
server_directory="${temporary_directory}/server"

mkdir -p "${server_directory}"

ipv4_match_port=18110
ipv4_rejected_port=18111
ipv6_match_port=18112
pid_first_port=18113
pid_second_port=18114
pid_rejected_port=18115

combined_table_output="${temporary_directory}/combined-table.txt"
combined_table_log="${temporary_directory}/combined-table.log"

pid_table_output="${temporary_directory}/pid-table.txt"
pid_table_log="${temporary_directory}/pid-table.log"

uid_table_output="${temporary_directory}/uid-table.txt"
uid_table_log="${temporary_directory}/uid-table.log"

ipv6_ndjson_output="${temporary_directory}/ipv6-events.ndjson"
ipv6_ndjson_log="${temporary_directory}/ipv6-events.log"

declare -a background_pids=()

tracer_pid=""

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
	"127.0.0.1" \
	"${ipv4_match_port}" \
	"${temporary_directory}/http-ipv4-match.log"

start_http_server \
	"127.0.0.1" \
	"${ipv4_rejected_port}" \
	"${temporary_directory}/http-ipv4-rejected.log"

start_http_server \
	"::1" \
	"${ipv6_match_port}" \
	"${temporary_directory}/http-ipv6-match.log"

start_http_server \
	"127.0.0.1" \
	"${pid_first_port}" \
	"${temporary_directory}/http-pid-first.log"

start_http_server \
	"127.0.0.1" \
	"${pid_second_port}" \
	"${temporary_directory}/http-pid-second.log"

start_http_server \
	"127.0.0.1" \
	"${pid_rejected_port}" \
	"${temporary_directory}/http-pid-rejected.log"

sleep 1

for server_pid in "${background_pids[@]}"; do
	if ! kill -0 "${server_pid}" 2>/dev/null; then
		echo "kernel-filter HTTP server exited during startup" >&2
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
		"$@" \
		>"${output_path}" \
		2>"${log_path}" &

	tracer_pid=$!

	sleep 2

	if ! kill -0 "${tracer_pid}" 2>/dev/null; then
		echo "kernel-filter tracer exited before requests were generated" >&2
		echo "--- tracer log ---" >&2
		cat "${log_path}" >&2 || true
		wait "${tracer_pid}" || true
		exit 1
	fi
}

wait_for_tracer() {
	local log_path="$1"

	if ! wait "${tracer_pid}"; then
		echo "kernel-filter tracer exited unsuccessfully" >&2
		echo "--- tracer log ---" >&2
		cat "${log_path}" >&2 || true
		exit 1
	fi

	tracer_pid=""
}

require_loss_summary() {
	local log_path="$1"

	if ! grep -Eq \
		'ring-buffer event loss summary: total=[0-9]+' \
		"${log_path}"
	then
		echo "tracer log did not contain an event-loss summary" >&2
		echo "--- tracer log ---" >&2
		cat "${log_path}" >&2
		exit 1
	fi
}

make_ipv4_requests() {
	local port="$1"

	for attempt in 1 2 3 4 5; do
		curl \
			--ipv4 \
			--noproxy '*' \
			--fail \
			--silent \
			--show-error \
			"http://127.0.0.1:${port}/" \
			>/dev/null

		sleep 0.1
	done
}

make_root_ipv4_requests() {
	local port="$1"

	for attempt in 1 2 3 4 5; do
		sudo curl \
			--ipv4 \
			--noproxy '*' \
			--fail \
			--silent \
			--show-error \
			"http://127.0.0.1:${port}/" \
			>/dev/null

		sleep 0.1
	done
}

make_ipv6_requests() {
	local port="$1"

	for attempt in 1 2 3 4 5; do
		curl \
			--ipv6 \
			--noproxy '*' \
			--fail \
			--silent \
			--show-error \
			"http://[::1]:${port}/" \
			>/dev/null

		sleep 0.1
	done
}

table_contains_port() {
	local output_path="$1"
	local expected_port="$2"

	awk \
		-v expected_port="${expected_port}" \
		'
		NR > 1 && $NF == expected_port {
			found = 1
		}

		END {
			exit found ? 0 : 1
		}
		' \
		"${output_path}"
}

table_contains_pid_and_port() {
	local output_path="$1"
	local expected_pid="$2"
	local expected_port="$3"

	awk \
		-v expected_pid="${expected_pid}" \
		-v expected_port="${expected_port}" \
		'
		NR > 1 &&
		$3 == expected_pid &&
		$NF == expected_port {
			found = 1
		}

		END {
			exit found ? 0 : 1
		}
		' \
		"${output_path}"
}

fail_table_test() {
	local message="$1"
	local output_path="$2"
	local log_path="$3"

	echo "${message}" >&2
	echo "--- table output ---" >&2
	cat "${output_path}" >&2 || true
	echo "--- tracer log ---" >&2
	cat "${log_path}" >&2 || true
	exit 1
}

# Test family and port filters together.
#
# Both the IPv4 and IPv6 target ports are present in the port filter. The IPv6
# request must therefore be rejected by the family filter rather than by the
# port filter.
run_tracer \
	"${combined_table_output}" \
	"${combined_table_log}" \
	--family ipv4 \
	--port "${ipv4_match_port}" \
	--port "${ipv6_match_port}"

make_ipv4_requests "${ipv4_match_port}"
make_ipv4_requests "${ipv4_rejected_port}"
make_ipv6_requests "${ipv6_match_port}"

wait_for_tracer "${combined_table_log}"
require_loss_summary "${combined_table_log}"

if ! table_contains_port \
	"${combined_table_output}" \
	"${ipv4_match_port}"
then
	fail_table_test \
		"combined filters did not emit the matching IPv4 destination" \
		"${combined_table_output}" \
		"${combined_table_log}"
fi

if table_contains_port \
	"${combined_table_output}" \
	"${ipv4_rejected_port}"
then
	fail_table_test \
		"combined filters emitted a non-matching destination port" \
		"${combined_table_output}" \
		"${combined_table_log}"
fi

if table_contains_port \
	"${combined_table_output}" \
	"${ipv6_match_port}"
then
	fail_table_test \
		"IPv4 family filter emitted an IPv6 destination" \
		"${combined_table_output}" \
		"${combined_table_log}"
fi

# Test OR semantics inside the PID category and exclusion of another PID.
first_pid_trigger="${temporary_directory}/first-pid-trigger"
second_pid_trigger="${temporary_directory}/second-pid-trigger"
rejected_pid_trigger="${temporary_directory}/rejected-pid-trigger"

start_requester() {
	local variable_name="$1"
	local trigger_path="$2"
	local host="$3"
	local port="$4"

	python3 - \
		"${trigger_path}" \
		"${host}" \
		"${port}" <<'PY' &
import pathlib
import socket
import sys
import time

trigger_path = pathlib.Path(sys.argv[1])
host = sys.argv[2]
port = int(sys.argv[3])

deadline = time.monotonic() + 15

while not trigger_path.exists():
    if time.monotonic() >= deadline:
        raise SystemExit("request trigger was not created")

    time.sleep(0.05)

for _ in range(5):
    with socket.create_connection(
        (host, port),
        timeout=3,
    ) as connection:
        connection.sendall(
            b"GET / HTTP/1.0\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )

        while connection.recv(4096):
            pass

    time.sleep(0.1)

# Keep /proc metadata available while userspace drains the ring buffer.
time.sleep(2)
PY

	local requester_pid=$!

	background_pids+=("${requester_pid}")

	printf -v \
		"${variable_name}" \
		'%s' \
		"${requester_pid}"
}

first_requester_pid=""
second_requester_pid=""
rejected_requester_pid=""

start_requester \
	first_requester_pid \
	"${first_pid_trigger}" \
	"127.0.0.1" \
	"${pid_first_port}"

start_requester \
	second_requester_pid \
	"${second_pid_trigger}" \
	"127.0.0.1" \
	"${pid_second_port}"

start_requester \
	rejected_requester_pid \
	"${rejected_pid_trigger}" \
	"127.0.0.1" \
	"${pid_rejected_port}"

run_tracer \
	"${pid_table_output}" \
	"${pid_table_log}" \
	--pid "${first_requester_pid}" \
	--pid "${second_requester_pid}"

touch \
	"${first_pid_trigger}" \
	"${second_pid_trigger}" \
	"${rejected_pid_trigger}"

if ! wait "${first_requester_pid}"; then
	echo "first allowed PID requester failed" >&2
	exit 1
fi

if ! wait "${second_requester_pid}"; then
	echo "second allowed PID requester failed" >&2
	exit 1
fi

if ! wait "${rejected_requester_pid}"; then
	echo "rejected PID requester failed" >&2
	exit 1
fi

wait_for_tracer "${pid_table_log}"
require_loss_summary "${pid_table_log}"

if ! table_contains_pid_and_port \
	"${pid_table_output}" \
	"${first_requester_pid}" \
	"${pid_first_port}"
then
	fail_table_test \
		"PID filter did not emit the first allowed PID" \
		"${pid_table_output}" \
		"${pid_table_log}"
fi

if ! table_contains_pid_and_port \
	"${pid_table_output}" \
	"${second_requester_pid}" \
	"${pid_second_port}"
then
	fail_table_test \
		"PID filter did not emit the second allowed PID" \
		"${pid_table_output}" \
		"${pid_table_log}"
fi

if table_contains_port \
	"${pid_table_output}" \
	"${pid_rejected_port}"
then
	fail_table_test \
		"PID filter emitted an event from a non-matching PID" \
		"${pid_table_output}" \
		"${pid_table_log}"
fi

# Test UID filtering when the invoking user is not root.
runner_uid="$(id -u)"

if [[ "${runner_uid}" != "0" ]]; then
	run_tracer \
		"${uid_table_output}" \
		"${uid_table_log}" \
		--uid "${runner_uid}"

	make_ipv4_requests "${ipv4_match_port}"
	make_root_ipv4_requests "${ipv4_rejected_port}"

	wait_for_tracer "${uid_table_log}"
	require_loss_summary "${uid_table_log}"

	if ! table_contains_port \
		"${uid_table_output}" \
		"${ipv4_match_port}"
	then
		fail_table_test \
			"UID filter did not emit the invoking user's request" \
			"${uid_table_output}" \
			"${uid_table_log}"
	fi

	if table_contains_port \
		"${uid_table_output}" \
		"${ipv4_rejected_port}"
	then
		fail_table_test \
			"UID filter emitted a root-owned request" \
			"${uid_table_output}" \
			"${uid_table_log}"
	fi
else
	echo "Skipping non-root UID filter test because the script runs as root."
fi

# Test the IPv6 family filter and NDJSON exclusion behavior.
run_tracer \
	"${ipv6_ndjson_output}" \
	"${ipv6_ndjson_log}" \
	--family ipv6 \
	--output ndjson

make_ipv4_requests "${ipv4_match_port}"
make_ipv6_requests "${ipv6_match_port}"

wait_for_tracer "${ipv6_ndjson_log}"
require_loss_summary "${ipv6_ndjson_log}"

python3 - \
	"${ipv6_ndjson_output}" \
	"${ipv4_match_port}" \
	"${ipv6_match_port}" <<'PY'
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
ipv4_port = int(sys.argv[2])
ipv6_port = int(sys.argv[3])

if not output_path.exists():
    raise SystemExit("IPv6-filter NDJSON output was not created")

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
            f"invalid filtered NDJSON on line {line_number}: {error}"
        ) from error

    if event.get("schema_version") != 1:
        raise SystemExit(
            f"unexpected schema version on filtered line {line_number}"
        )

    if event.get("event_type") != "connect_attempt":
        raise SystemExit(
            f"unexpected event type on filtered line {line_number}"
        )

    events.append(event)

if not events:
    raise SystemExit("IPv6 family filter produced no NDJSON events")

matching_ipv6_events = [
    event
    for event in events
    if (
        event.get("address_family") == "AF_INET6"
        and event.get("destination", {}).get("ip") == "::1"
        and event.get("destination", {}).get("port") == ipv6_port
        and event.get("process", {}).get("comm") == "curl"
    )
]

if not matching_ipv6_events:
    raise SystemExit(
        f"IPv6 family filter produced no event for [::1]:{ipv6_port}"
    )

matching_ipv4_events = [
    event
    for event in events
    if event.get("destination", {}).get("port") == ipv4_port
]

if matching_ipv4_events:
    raise SystemExit(
        f"IPv6 family filter emitted IPv4 port {ipv4_port}"
    )

unexpected_ipv4_events = [
    event
    for event in events
    if event.get("address_family") == "AF_INET"
]

if unexpected_ipv4_events:
    raise SystemExit(
        "IPv6 family filter emitted one or more AF_INET events"
    )
PY

echo "Kernel-filter integration tests passed."
