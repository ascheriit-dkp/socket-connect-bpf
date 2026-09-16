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

import json
import sys


def format_failure(event):
    process = event.get("process", {})
    remote = event.get("remote", {})

    if not isinstance(process, dict):
        process = {}
    if not isinstance(remote, dict):
        remote = {}

    process_name = process.get("comm") or process.get("executable") or "?"
    remote_ip = remote.get("ip", "?")
    remote_port = remote.get("port", "?")
    errno = event.get("errno", "?")
    error = event.get("error", "")

    message = (
        f"tcp_connect_failed process={process_name} "
        f"remote={remote_ip}:{remote_port} errno={errno}"
    )
    if error:
        message += f" error={error}"
    return message


def main():
    failures = 0

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

        if (
            event.get("schema_version") == 2
            and event.get("event_type") == "tcp_connect_failed"
        ):
            failures += 1
            print(format_failure(event), file=sys.stderr)

    if failures:
        print(f"TCP failures observed: {failures}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
