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

for command in git python3 sha256sum; do
	if ! command -v "${command}" >/dev/null 2>&1; then
		echo "required command not found: ${command}" >&2
		exit 1
	fi
done

artifacts_directory="${1:-artifacts}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

if [[ ! "${source_date_epoch}" =~ ^[0-9]+$ ]]; then
	echo \
		"SOURCE_DATE_EPOCH must be an unsigned Unix timestamp: " \
		"${source_date_epoch}" >&2
	exit 1
fi

if [[ ! -d "${artifacts_directory}" ]]; then
	echo "artifacts directory not found: ${artifacts_directory}" >&2
	exit 1
fi

checksum_path="${artifacts_directory}/SHA256SUMS"

if [[ ! -f "${checksum_path}" ]]; then
	echo "checksum manifest not found: ${checksum_path}" >&2
	exit 1
fi

expected_archives=(
	"socket-connect-bpf-linux-amd64.tar.gz"
	"socket-connect-bpf-linux-arm64.tar.gz"
)

for archive_name in "${expected_archives[@]}"; do
	archive_path="${artifacts_directory}/${archive_name}"

	if [[ ! -f "${archive_path}" ]]; then
		echo "release archive not found: ${archive_path}" >&2
		exit 1
	fi
done

mapfile -t checksum_entries < <(
	awk '
		NF == 2 {
			filename =	NF == 2 {
			filename = $2
			sub(/^\*/, "", filename)
			print filename
		}
	' "${checksum_path}" |
		LC_ALL=C sort
)

mapfile -t expected_checksum_entries < <(
	printf '%s\n' "${expected_archives[@]}" |
		LC_ALL=C sort
)

if [[ "${#checksum_entries[@]}" -ne "${#expected_checksum_entries[@]}" ]]; then
	echo "SHA256SUMS contains an unexpected number of entries" >&2
	printf 'actual entries:\n' >&2
	printf '  %s\n' "${checksum_entries[@]}" >&2
	exit 1
fi

for index in "${!expected_checksum_entries[@]}"; do
	if [[ \
		"${checksum_entries[${index}]}" \
		!= "${expected_checksum_entries[${index}]}" \
	]]; then
		echo "SHA256SUMS contains unexpected archive names" >&2
		printf 'expected entries:\n' >&2
		printf '  %s\n' "${expected_checksum_entries[@]}" >&2
		printf 'actual entries:\n' >&2
		printf '  %s\n' "${checksum_entries[@]}" >&2
		exit 1
	fi
done

(
	cd "${artifacts_directory}"
	sha256sum --check --strict SHA256SUMS
)

python3 - \
	"${artifacts_directory}" \
	"${source_date_epoch}" \
	"${expected_archives[@]}" <<'PY'
import gzip
import pathlib
import sys
import tarfile

artifacts_directory = pathlib.Path(sys.argv[1])
expected_timestamp = int(sys.argv[2])
archive_names = sys.argv[3:]

expected_members = {
    "": ("directory", 0o755),
    "as": ("directory", 0o755),
    "socket-connect-bpf": ("file", 0o755),
    "README.md": ("file", 0o644),
    "LICENSE": ("file", 0o644),
    "LICENSING.md": ("file", 0o644),
    "THIRD_PARTY_NOTICES.md": ("file", 0o644),
    "SECURITY.md": ("file", 0o644),
    "as/ip2asn-v4-u32.tsv": ("file", 0o644),
    "as/ip2asn-v6.tsv": ("file", 0o644),
}


def normalize_member_name(name: str) -> str:
    if name == ".":
        return ""

    if name.startswith("./"):
        name = name[2:]

    return name.rstrip("/")


for archive_name in archive_names:
    archive_path = artifacts_directory / archive_name

    with archive_path.open("rb") as archive_file:
        gzip_header = archive_file.read(10)

    if len(gzip_header) != 10:
        raise SystemExit(
            f"{archive_name}: truncated gzip header"
        )

    if gzip_header[0:2] != b"\x1f\x8b":
        raise SystemExit(
            f"{archive_name}: invalid gzip signature"
        )

    gzip_flags = gzip_header[3]
    gzip_timestamp = int.from_bytes(
        gzip_header[4:8],
        byteorder="little",
    )

    if gzip_flags != 0:
        raise SystemExit(
            f"{archive_name}: gzip header contains optional metadata"
        )

    if gzip_timestamp != 0:
        raise SystemExit(
            f"{archive_name}: gzip timestamp is not normalized"
        )

    observed_members = {}

    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            normalized_name = normalize_member_name(member.name)
            member_path = pathlib.PurePosixPath(normalized_name)

            if member.name.startswith("/"):
                raise SystemExit(
                    f"{archive_name}: absolute archive path: "
                    f"{member.name}"
                )

            if ".." in member_path.parts:
                raise SystemExit(
                    f"{archive_name}: parent traversal path: "
                    f"{member.name}"
                )

            if normalized_name in observed_members:
                raise SystemExit(
                    f"{archive_name}: duplicate archive member: "
                    f"{normalized_name}"
                )

            observed_members[normalized_name] = member

    expected_names = set(expected_members)
    observed_names = set(observed_members)

    missing_names = sorted(expected_names - observed_names)
    unexpected_names = sorted(observed_names - expected_names)

    if missing_names:
        raise SystemExit(
            f"{archive_name}: missing members: "
            + ", ".join(missing_names)
        )

    if unexpected_names:
        raise SystemExit(
            f"{archive_name}: unexpected members: "
            + ", ".join(unexpected_names)
        )

    for member_name, (expected_type, expected_mode) in (
        expected_members.items()
    ):
        member = observed_members[member_name]

        if expected_type == "directory":
            valid_type = member.isdir()
        else:
            valid_type = member.isfile()

        if not valid_type:
            raise SystemExit(
                f"{archive_name}: invalid member type for "
                f"{member_name or '.'}"
            )

        actual_mode = member.mode & 0o777

        if actual_mode != expected_mode:
            raise SystemExit(
                f"{archive_name}: invalid mode for "
                f"{member_name or '.'}: "
                f"{actual_mode:o}, expected {expected_mode:o}"
            )

        if member.uid != 0 or member.gid != 0:
            raise SystemExit(
                f"{archive_name}: non-normalized ownership for "
                f"{member_name or '.'}: "
                f"uid={member.uid} gid={member.gid}"
            )

        if member.mtime != expected_timestamp:
            raise SystemExit(
                f"{archive_name}: non-normalized timestamp for "
                f"{member_name or '.'}: "
                f"{member.mtime}, expected {expected_timestamp}"
            )

    with gzip.open(archive_path, mode="rb") as compressed_file:
        while compressed_file.read(1024 * 1024):
            pass

    print(f"{archive_name}: verified")


print("Release artifacts verified successfully.")
PY
