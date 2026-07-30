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

export LC_ALL=C

script_directory="$(
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
	pwd
)"
repository_root="$(
	cd -- "${script_directory}/.."
	pwd
)"

cd "${repository_root}"

dirty_worktree="false"

if [[ -n "$(git status --porcelain 2>/dev/null || true)" ]]; then
	dirty_worktree="true"
fi

requested_output="${1:-benchmark-results/benchmarks.txt}"

if [[ "${requested_output}" = /* ]]; then
	output_path="${requested_output}"
else
	output_path="${repository_root}/${requested_output}"
fi

benchmark_count="${BENCHMARK_COUNT:-5}"
benchmark_time="${BENCHMARK_TIME:-250ms}"
benchmark_cpu="${BENCHMARK_CPU:-1,2,4}"

mkdir -p "$(dirname -- "${output_path}")"

commit_sha="$(
	git rev-parse HEAD 2>/dev/null ||
		printf '%s\n' "unknown"
)"

cpu_model="unknown"

if command -v lscpu >/dev/null 2>&1; then
	detected_cpu_model="$(
		lscpu |
			awk -F: '
				$1 ~ /^Model name/ {
					sub(/^[[:space:]]+/, "", $2)
					print $2
					exit
				}
			'
	)"

	if [[ -n "${detected_cpu_model}" ]]; then
		cpu_model="${detected_cpu_model}"
	fi
fi

logical_cpu_count="$(
	getconf _NPROCESSORS_ONLN 2>/dev/null ||
		printf '%s\n' "unknown"
)"

{
	printf '%s\n' "# socket-connect-bpf benchmark results"
	printf '\n'
	printf 'timestamp_utc: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf 'commit: %s\n' "${commit_sha}"
	printf 'dirty_worktree: %s\n' "${dirty_worktree}"
	printf 'go_version: %s\n' "$(go version)"
	printf 'goos: %s\n' "$(go env GOOS)"
	printf 'goarch: %s\n' "$(go env GOARCH)"
	printf 'kernel: %s\n' "$(uname -sr)"
	printf 'machine: %s\n' "$(uname -m)"
	printf 'cpu_model: %s\n' "${cpu_model}"
	printf 'logical_cpus: %s\n' "${logical_cpu_count}"
	printf 'benchmark_count: %s\n' "${benchmark_count}"
	printf 'benchmark_time: %s\n' "${benchmark_time}"
	printf 'benchmark_cpu: %s\n' "${benchmark_cpu}"
	printf '\n'
	printf '%s\n' \
		"Results from shared CI runners are observational and are not performance gates."
	printf '\n'
	printf 'command: make benchmark BENCHMARK_COUNT=%q BENCHMARK_TIME=%q BENCHMARK_CPU=%q\n' \
		"${benchmark_count}" \
		"${benchmark_time}" \
		"${benchmark_cpu}"
	printf '\n'
} >"${output_path}"

make benchmark \
	BENCHMARK_COUNT="${benchmark_count}" \
	BENCHMARK_TIME="${benchmark_time}" \
	BENCHMARK_CPU="${benchmark_cpu}" \
	2>&1 |
	tee -a "${output_path}"
