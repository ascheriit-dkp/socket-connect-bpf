#!/usr/bin/env python3

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

import csv
import json
import sys


COLUMNS = (
    "schema_version",
    "event_type",
    "observed_at",
    "protocol",
    "pid",
    "uid",
    "comm",
    "remote_ip",
    "remote_port",
    "result",
    "errno",
    "dns_name",
    "dns_confidence",
    "asn_number",
)


def object_field(value, key):
    if isinstance(value, dict):
        return value.get(key, "")
    return ""


def endpoint_for_event(event):
    if event.get("schema_version") == 1:
        endpoint = event.get("destination", {})
    else:
        endpoint = event.get("remote", {})

    if not isinstance(endpoint, dict):
        return {}
    return endpoint


def row_for_event(event):
    process = event.get("process", {})
    dns = event.get("dns", {})
    asn = event.get("asn", {})
    endpoint = endpoint_for_event(event)

    return {
        "schema_version": event.get("schema_version", ""),
        "event_type": event.get("event_type", ""),
        "observed_at": event.get("observed_at", ""),
        "protocol": event.get("protocol", ""),
        "pid": object_field(process, "pid"),
        "uid": object_field(process, "uid"),
        "comm": object_field(process, "comm"),
        "remote_ip": endpoint.get("ip", ""),
        "remote_port": endpoint.get("port", ""),
        "result": event.get("result", ""),
        "errno": event.get("errno", ""),
        "dns_name": object_field(dns, "name"),
        "dns_confidence": object_field(dns, "confidence"),
        "asn_number": object_field(asn, "number"),
    }


def main():
    writer = csv.DictWriter(sys.stdout, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()

    for line_number, line in enumerate(sys.stdin, start=1):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            print(
                f"invalid JSON on line {line_number}: {error}",
                file=sys.stderr,
            )
            return 2

        if not isinstance(event, dict):
            print(
                f"line {line_number} is not a JSON object",
                file=sys.stderr,
            )
            return 2

        writer.writerow(row_for_event(event))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
