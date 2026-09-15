# Benchmarks

## Purpose

These benchmarks establish reproducible userspace performance baselines for
socket-connect-bpf v2.

They make output and enrichment changes measurable. They are not performance
guarantees, release gates, or substitutes for end-to-end tracing benchmarks.

## Current scope

The benchmark suite measures:

- Terminal sanitization of clean process data.
- Terminal sanitization of control characters and escape sequences.
- Terminal sanitization of Unicode formatting characters.
- Terminal sanitization of long process arguments.
- Human-readable table serialization.
- NDJSON serialization.
- Basic output without extended process or ASN fields.
- Extended output with arguments and ASN fields.
- Serial output calls.
- Concurrent output calls contending on the output mutex.
- Indexed IPv4 ASN lookup latency and allocations.
- Indexed IPv6 ASN lookup latency and allocations.

The output benchmarks write to `io.Discard`.

They therefore measure event formatting, serialization, allocation, locking,
and in-memory ASN lookup costs without including terminal, pipe, filesystem,
or network I/O.

## ASN lookup benchmarks

Phase 6 sorts ASN ranges once while loading the enrichment datasets and uses
binary search for lookups instead of scanning every candidate range.

The focused benchmarks use:

- 32,768 synthetic IPv4 ranges in one first-octet bucket;
- 65,536 synthetic IPv6 ranges;
- a successful lookup near the end of each data set.

An observational GitHub Actions run on an AMD EPYC 9V74 shared runner with Go
1.23.12 reported approximately:

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Indexed IPv4 ASN lookup | 54 | 0 | 0 |
| Indexed IPv6 ASN lookup | 94 | 0 | 0 |

These values describe that runner and benchmark shape only. They are not a
throughput guarantee for the tracer or for arbitrary ASN datasets.

## Excluded costs

The current microbenchmarks do not measure:

- eBPF program execution.
- Ring-buffer delivery or kernel-to-userspace transfer.
- Event loss under load.
- `/proc` process enrichment.
- ASN dataset parsing or load-time sorting.
- Terminal rendering.
- Disk or pipe throughput.
- Real connection-generation throughput.
- Complete tracer CPU or memory overhead.

Those areas require separate integration benchmarks.

## Running locally

Run the default benchmark configuration:

    make benchmark

The default configuration uses:

    BENCHMARK_COUNT=5
    BENCHMARK_TIME=250ms
    BENCHMARK_CPU=1,2,4

Override any parameter when needed:

    make benchmark \
      BENCHMARK_COUNT=10 \
      BENCHMARK_TIME=1s \
      BENCHMARK_CPU=1

To record benchmark output together with environment metadata:

    bash scripts/run-benchmarks.sh

The default report is written to:

    benchmark-results/benchmarks.txt

Supply a different output path as the first argument:

    bash scripts/run-benchmarks.sh /tmp/socket-connect-bpf-benchmarks.txt

## Recorded metadata

The benchmark runner records:

- UTC timestamp.
- Git commit.
- Whether the working tree contains changes.
- Go version.
- GOOS and GOARCH.
- Kernel release.
- Machine architecture.
- CPU model.
- Available logical CPU count.
- Benchmark count.
- Benchmark duration.
- Requested CPU configurations.
- The complete raw Go benchmark output.

Results should only be compared when the relevant environment and benchmark
parameters are sufficiently similar.

## Continuous integration

GitHub Actions runs the benchmark suite on the shared Linux runner and uploads:

    socket-connect-bpf-benchmarks

The artifact contains:

    benchmarks.txt

CI benchmark artifacts are retained for 14 days.

Shared runners can differ in hardware, host load, scheduling, and
virtualization. Their results are observational and are not used as automatic
performance thresholds.

## Interpreting results

The most useful Go benchmark columns are:

- `ns/op`: elapsed nanoseconds per operation.
- `B/op`: allocated bytes per operation.
- `allocs/op`: allocations per operation.

Lower values generally indicate less work or allocation, but a change should
not be judged from a single run.

Use repeated measurements and compare distributions rather than selecting one
favourable sample.

Parallel benchmark results include mutex contention and scheduler effects.
They should not be interpreted as direct tracer event-throughput limits.

## Comparison procedure

For a meaningful before-and-after comparison:

1. Use the same machine or runner class.
2. Use the same Go version.
3. Use the same benchmark parameters.
4. Avoid unrelated background load where practical.
5. Run both revisions several times.
6. Preserve the raw reports and environment metadata.
7. Investigate allocation changes as well as execution time.
8. Confirm important changes with an end-to-end workload.

Performance claims in project documentation must be supported by reproducible
results and must state what was and was not measured.

## Future benchmark work

Later work should add reproducible measurements for:

- ASN dataset parsing and load-time sorting.
- DNS correlation and other enrichment paths.
- Event decoding and enrichment.
- Ring-buffer throughput.
- Event loss under controlled load.
- Short-lived process attribution.
- End-to-end TCP and UDP event throughput.
- Tracer CPU and resident-memory overhead.
