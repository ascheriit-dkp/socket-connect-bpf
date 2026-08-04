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

for command in git gzip install mktemp sha256sum tar; do
	if ! command -v "${command}" >/dev/null 2>&1; then
		echo "required command not found: ${command}" >&2
		exit 1
	fi
done

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

if [[ ! "${source_date_epoch}" =~ ^[0-9]+$ ]]; then
	echo \
		"SOURCE_DATE_EPOCH must be an unsigned Unix timestamp: " \
		"${source_date_epoch}" >&2
	exit 1
fi

binary_name="socket-connect-bpf"
artifacts_directory="${repository_root}/artifacts"
temporary_directory="$(mktemp -d)"
staging_root="${temporary_directory}/staging"

cleanup() {
	rm -rf "${temporary_directory}"
}

trap cleanup EXIT

umask 022

rm -rf "${artifacts_directory}"
mkdir -p "${artifacts_directory}"
mkdir -p "${staging_root}"

required_documentation=(
	"README.md"
	"LICENSE"
	"LICENSING.md"
	"THIRD_PARTY_NOTICES.md"
	"SECURITY.md"
)

required_datasets=(
	"as/ip2asn-v4-u32.tsv"
	"as/ip2asn-v6.tsv"
)

for required_file in \
	"${required_documentation[@]}" \
	"${required_datasets[@]}"
do
	if [[ ! -f "${required_file}" ]]; then
		echo "required release file not found: ${required_file}" >&2
		exit 1
	fi
done

for architecture in amd64 arm64; do
	binary_path="bin/${architecture}/${binary_name}"
	package_directory="${staging_root}/${architecture}"
	archive_path="${artifacts_directory}/${binary_name}-linux-${architecture}.tar.gz"

	if [[ ! -f "${binary_path}" ]]; then
		echo "release binary not found: ${binary_path}" >&2
		exit 1
	fi

	mkdir -p "${package_directory}/as"

	install \
		-m 0755 \
		"${binary_path}" \
		"${package_directory}/${binary_name}"

	for documentation_file in "${required_documentation[@]}"; do
		install \
			-m 0644 \
			"${documentation_file}" \
			"${package_directory}/${documentation_file}"
	done

	for dataset_file in "${required_datasets[@]}"; do
		install \
			-m 0644 \
			"${dataset_file}" \
			"${package_directory}/as/$(basename "${dataset_file}")"
	done

	tar \
		--sort=name \
		--format=gnu \
		--mtime="@${source_date_epoch}" \
		--owner=0 \
		--group=0 \
		--numeric-owner \
		--mode="u+rwX,go+rX,go-w" \
		--directory="${package_directory}" \
		-cf - \
		. |
		gzip -n -9 >"${archive_path}"
done

(
	cd "${artifacts_directory}"

	sha256sum \
		"${binary_name}-linux-amd64.tar.gz" \
		"${binary_name}-linux-arm64.tar.gz" \
		>SHA256SUMS

	sha256sum --check SHA256SUMS
)

printf '%s\n' \
	"Created reproducible release artifacts:" \
	"  artifacts/${binary_name}-linux-amd64.tar.gz" \
	"  artifacts/${binary_name}-linux-arm64.tar.gz" \
	"  artifacts/SHA256SUMS" \
	"SOURCE_DATE_EPOCH=${source_date_epoch}"
