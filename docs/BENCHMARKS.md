# Benchmarks

## Purpose

These benchmarks establish the initial userspace performance baseline for
socket-connect-bpf v2.

They are intended to make future output-pipeline changes measurable and
reproducible.

They are not performance guarantees, release gates, or substitutes for
end-to-end tracing benchmarks.

## Current scope

The current benchmark suite measures:

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

The output benchmarks write to `io.Discard`.

They therefore measure event formatting, serialization, allocation, and
locking costs without including terminal, pipe, filesystem, or network I/O.

## Excluded costs

The current microbenchmarks do not measure:

- eBPF program execution.
- Perf-event delivery.
- Kernel-to-userspace transfer.
- Event loss under load.
- `/proc` process enrichment.
- ASN dataset loading.
- ASN lookup performance.
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

To record the benchmark output together with environment metadata:

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

Later phases should add reproducible measurements for:

- ASN lookup latency and memory use.
- Event decoding and enrichment.
- Ring-buffer throughput.
- Event loss under controlled load.
- Short-lived process attribution.
- End-to-end TCP and UDP event throughput.
- Tracer CPU and resident-memory overhead.
