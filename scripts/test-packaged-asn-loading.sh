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

archive="${1:-artifacts/socket-connect-bpf-linux-amd64.tar.gz}"
http_port="${2:-18081}"

if [[ ! -f "${archive}" ]]; then
	echo "release archive not found: ${archive}" >&2
	exit 1
fi

temporary_directory="$(mktemp -d)"
package_directory="${temporary_directory}/package"
working_directory="${temporary_directory}/unrelated-working-directory"
trace_output="${temporary_directory}/events.ndjson"
trace_log="${temporary_directory}/tracer.log"
server_log="${temporary_directory}/http-server.log"

mkdir -p "${package_directory}"
mkdir -p "${working_directory}"

tar xzf "${archive}" --directory="${package_directory}"

binary="${package_directory}/socket-connect-bpf"
ipv4_dataset="${package_directory}/as/ip2asn-v4-u32.tsv"
ipv6_dataset="${package_directory}/as/ip2asn-v6.tsv"

for required_file in \
	"${binary}" \
	"${ipv4_dataset}" \
	"${ipv6_dataset}"
do
	if [[ ! -f "${required_file}" ]]; then
		echo "packaged ASN integration test is missing ${required_file}" >&2
		exit 1
	fi
done

python3 -m http.server "${http_port}" \
	--bind 127.0.0.1 \
	--directory "${working_directory}" \
	>"${server_log}" 2>&1 &

server_pid=$!
tracer_pid=""

cleanup() {
	if [[ -n "${tracer_pid}" ]]; then
		kill "${tracer_pid}" 2>/dev/null || true
	fi

	kill "${server_pid}" 2>/dev/null || true
	rm -rf "${temporary_directory}"
}

trap cleanup EXIT

sleep 1

(
	cd "${working_directory}"

	sudo timeout \
		--preserve-status \
		--signal=INT \
		6s \
		"${binary}" \
		-a \
		--output ndjson \
		>"${trace_output}" \
		2>"${trace_log}"
) &

tracer_pid=$!

sleep 2

if ! kill -0 "${tracer_pid}" 2>/dev/null; then
	echo "packaged tracer exited before requests were generated" >&2
	echo "--- tracer log ---" >&2
	cat "${trace_log}" >&2 || true
	wait "${tracer_pid}" || true
	exit 1
fi

for attempt in 1 2 3 4 5; do
	curl \
		--fail \
		--silent \
		--show-error \
		"http://127.0.0.1:${http_port}/" \
		>/dev/null

	sleep 0.2
done

wait "${tracer_pid}"
tracer_pid=""

if grep -q "loading ASN data" "${trace_log}"; then
	echo "packaged tracer failed to load executable-relative ASN data" >&2
	echo "--- tracer log ---" >&2
	cat "${trace_log}" >&2
	exit 1
fi

python3 - "${trace_output}" "${http_port}" <<'PY'
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
expected_port = int(sys.argv[2])

if not output_path.exists():
    raise SystemExit("packaged tracer did not create NDJSON output")

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
            f"invalid packaged-tracer JSON on line {line_number}: {error}"
        ) from error

    events.append(event)

if not events:
    raise SystemExit("packaged tracer produced no NDJSON events")

matching_events = [
    event
    for event in events
    if event.get("destination", {}).get("port") == expected_port
]

if not matching_events:
    raise SystemExit(
        f"packaged tracer produced no event for port {expected_port}"
    )

if not any(
    event.get("destination", {}).get("ip") == "127.0.0.1"
    for event in matching_events
):
    raise SystemExit(
        "packaged tracer event did not contain destination 127.0.0.1"
    )

if not any(
    event.get("process", {}).get("comm") == "curl"
    for event in matching_events
):
    raise SystemExit(
        "packaged tracer event was not attributed to curl"
    )
PY
