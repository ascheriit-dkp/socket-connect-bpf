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

repository_root="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"

cd "${repository_root}"

for command in python3 mktemp grep; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required command not found: ${command}" >&2
        exit 1
    fi
done

python3 -m py_compile \
    examples/ndjson_to_csv.py \
    examples/check_tcp_failures.py

temporary_directory="$(mktemp -d)"
cleanup() {
    rm -rf "${temporary_directory}"
    rm -rf examples/__pycache__
}
trap cleanup EXIT

fixture="${temporary_directory}/events.ndjson"
csv_output="${temporary_directory}/events.csv"

cat >"${fixture}" <<'EOF'
{"schema_version":1,"event_type":"connect_attempt","observed_at":"2026-09-16T12:00:00Z","protocol":"tcp","process":{"pid":11,"uid":1000,"comm":"curl"},"destination":{"ip":"192.0.2.10","port":443}}
{"schema_version":2,"event_type":"tcp_established","observed_at":"2026-09-16T12:00:01Z","protocol":"tcp","process":{"pid":12,"uid":1000,"comm":"client"},"remote":{"ip":"198.51.100.20","port":443},"result":"success","dns":{"name":"service.example","source":"resolver-log","confidence":"medium"},"asn":{"number":64500,"name":"EXAMPLE"}}
{"schema_version":3,"event_type":"udp_send","observed_at":"2026-09-16T12:00:02Z","protocol":"udp","process":{"pid":13,"uid":1000,"comm":"sender"},"remote":{"ip":"203.0.113.30","port":53}}
EOF

python3 examples/ndjson_to_csv.py <"${fixture}" >"${csv_output}"

python3 - "${csv_output}" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open(newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))

if len(rows) != 3:
    raise SystemExit(f"CSV row count = {len(rows)}, want 3")

if rows[0]["schema_version"] != "1":
    raise SystemExit("schema v1 row missing")
if rows[0]["remote_ip"] != "192.0.2.10":
    raise SystemExit("schema v1 destination mapping failed")
if rows[1]["dns_name"] != "service.example":
    raise SystemExit("schema v2 DNS export failed")
if rows[1]["dns_confidence"] != "medium":
    raise SystemExit("schema v2 DNS confidence export failed")
if rows[1]["asn_number"] != "64500":
    raise SystemExit("schema v2 ASN export failed")
if rows[2]["protocol"] != "udp":
    raise SystemExit("schema v3 protocol export failed")
if rows[2]["remote_port"] != "53":
    raise SystemExit("schema v3 remote port export failed")
PY

success_fixture="${temporary_directory}/success.ndjson"
cat >"${success_fixture}" <<'EOF'
{"schema_version":2,"event_type":"tcp_established","process":{"comm":"client"},"remote":{"ip":"192.0.2.1","port":443},"result":"success"}
EOF

python3 examples/check_tcp_failures.py <"${success_fixture}"

failure_fixture="${temporary_directory}/failure.ndjson"
failure_log="${temporary_directory}/failure.log"
cat >"${failure_fixture}" <<'EOF'
{"schema_version":2,"event_type":"tcp_connect_failed","process":{"comm":"client"},"remote":{"ip":"192.0.2.2","port":443},"result":"failed","errno":111,"error":"connection refused"}
EOF

set +e
python3 examples/check_tcp_failures.py \
    <"${failure_fixture}" \
    2>"${failure_log}"
failure_status=$?
set -e

if [[ "${failure_status}" -ne 1 ]]; then
    echo "TCP failure gate exited ${failure_status}; want 1" >&2
    exit 1
fi

if ! grep -Fq 'TCP failures observed: 1' "${failure_log}"; then
    echo "TCP failure gate did not report the observed failure" >&2
    cat "${failure_log}" >&2
    exit 1
fi

python3 - examples/dns-observations.example.jsonl <<'PY'
import ipaddress
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
records = []
for line_number, line in enumerate(
    path.read_text(encoding="utf-8").splitlines(),
    start=1,
):
    if not line.strip():
        continue
    try:
        record = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"invalid DNS example JSON on line {line_number}: {error}"
        ) from error
    if not isinstance(record, dict):
        raise SystemExit(f"DNS example line {line_number} is not an object")
    for field in ("ip", "name", "observed_at", "ttl_seconds"):
        if field not in record:
            raise SystemExit(
                f"DNS example line {line_number} is missing {field}"
            )
    ipaddress.ip_address(record["ip"])
    if not isinstance(record["ttl_seconds"], int) or record["ttl_seconds"] <= 0:
        raise SystemExit(
            f"DNS example line {line_number} has invalid ttl_seconds"
        )
    records.append(record)

if len(records) != 2:
    raise SystemExit(f"DNS example record count = {len(records)}, want 2")
PY

echo "Export and integration examples passed."
