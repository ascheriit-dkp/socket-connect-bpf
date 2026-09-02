# socket-connect-bpf

socket-connect-bpf is a lightweight Linux command-line tracer for
process-aware outbound socket activity using eBPF.

It supports two collection modes:

- the compatibility mode, which reports outbound connection attempts exactly as
  the existing v2 interface does;
- TCP lifecycle mode, enabled explicitly with `--tcp-lifecycle`, which follows
  outbound IPv4 and IPv6 TCP connections from attempt through establishment,
  failure, and closure.

Both modes can produce a human-readable table or newline-delimited JSON
(NDJSON).

![socket-connect-bpf while making a request with curl](samples/socket-connect-bpf.gif)

## TCP lifecycle mode

Enable lifecycle tracking with:

    sudo ./socket-connect-bpf --tcp-lifecycle

Lifecycle mode emits four event types:

- `connect_attempt`
- `tcp_established`
- `tcp_connect_failed`
- `tcp_closed`

Events belonging to the same tracked TCP connection share one opaque
`connection_id` for the duration of the tracer process.

Successful connections expose connect latency and, after closure, established
connection duration. Established and closed events include the observed local
and remote TCP tuple when available.

Use lifecycle NDJSON with:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --output ndjson

Lifecycle NDJSON uses schema version `2`. The complete contract is documented
in [TCP lifecycle contract](docs/TCP_LIFECYCLE.md) and
[NDJSON Event Schema v2](docs/EVENT_SCHEMA_V2.md).

### Compatibility

Without `--tcp-lifecycle`, existing behavior is unchanged:

- collection remains attempt-only;
- the existing table format remains unchanged;
- NDJSON remains schema version `1`;
- existing PID, UID, family, and destination-port filter semantics remain
  unchanged.

The attempt-only NDJSON contract is documented in
[NDJSON Event Schema v1](docs/EVENT_SCHEMA_V1.md).

## How lifecycle tracking works

The lifecycle implementation uses bounded eBPF correlation maps and one shared
ring buffer.

Outbound TCP attempts are captured for IPv4 and IPv6. Later TCP state changes
are correlated with the initiating attempt so the tracer can distinguish a
successful establishment from a terminal failure and can report closure after
establishment.

The initiating process identity and the filter decision are preserved for later
lifecycle events. Later kernel state transitions are not re-attributed to a
process that merely happens to execute the transition.

The tracer does not expose raw kernel socket pointers. `connection_id` is an
opaque per-run identifier.

## Output

### Attempt-only table

Run the compatibility table output with:

    sudo ./socket-connect-bpf

The existing table reports information such as observation time, address
family, process, user, destination, and optional autonomous-system metadata.

### Lifecycle table

Run the lifecycle table with:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --output table

The lifecycle table includes the event type, process, user, local and remote
endpoints, result, error, connect latency, connection duration, and optional
ASN information.

### Attempt-only NDJSON

    sudo ./socket-connect-bpf --output ndjson

This emits schema version `1` and `connect_attempt` events only.

### Lifecycle NDJSON

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --output ndjson

This emits schema version `2` and never mixes version 1 and version 2 records in
the same stream.

Diagnostics and errors are written to standard error rather than mixed into the
NDJSON stream.

## Extended information

Use `-a` to include additional process information and autonomous-system
metadata:

    sudo ./socket-connect-bpf -a

It can be combined with lifecycle mode:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      -a \
      --output ndjson

Lifecycle mode caches initiating-process enrichment by `connection_id` in a
bounded userspace cache so later establishment or closure events can preserve
metadata for short-lived processes.

## Kernel-side filtering

The tracer supports kernel-side filters for:

- process ID with `--pid`;
- user ID with `--uid`;
- address-family category with `--family`;
- destination port with `--port`.

Each option may be repeated.

Example:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --uid 1000 \
      --family ipv4 \
      --port 80 \
      --port 443 \
      --output ndjson

Values inside one category use OR semantics. Different categories use AND
semantics.

Supported family values are:

| Value | Matching events |
| --- | --- |
| `ipv4` | `AF_INET` |
| `ipv6` | `AF_INET6` |
| `other` | Supported non-IP families in attempt-only mode |

Lifecycle mode currently tracks outbound IPv4 and IPv6 TCP connections.

The filter decision is made at the initiating attempt. Only accepted attempts
create lifecycle correlation state, and later lifecycle events inherit that
decision.

The complete filter contract is documented in
[Kernel-side filter contract](docs/KERNEL_FILTERS.md).

## Event loss and lifecycle diagnostics

The shared ring buffer counts matching events that could not be submitted
because space was unavailable.

At shutdown the tracer reports:

    ring-buffer event loss summary: total=0

Lifecycle mode also reports bounded-correlation diagnostics:

    TCP lifecycle diagnostic summary: map_update_failures=0 missing_correlation=0 unsupported_observations=0

Non-zero diagnostic values indicate that one or more lifecycle observations
could not be correlated or represented reliably. They are diagnostics, not
fabricated public lifecycle events.

## Autonomous-system data

Autonomous-system enrichment uses datasets from
[IPtoASN](https://iptoasn.com/).

Datasets are loaded only when `-a` is enabled.

By default the tracer loads an `as/` directory beside the resolved executable:

    package/
    ├── socket-connect-bpf
    └── as/
        ├── ip2asn-v4-u32.tsv
        └── ip2asn-v6.tsv

Override the directory with:

    sudo ./socket-connect-bpf \
      -a \
      --asn-dir /var/lib/socket-connect-bpf/as

When `-a` is enabled, missing or malformed ASN data causes startup to fail with
a descriptive error.

Developers can refresh the datasets with:

    ./updateASData.sh

## Command-line options

    --tcp-lifecycle
        Track outbound IPv4 and IPv6 TCP attempts, establishment, failures,
        and closure. Lifecycle NDJSON uses schema version 2.

    -a
        Include process arguments and autonomous-system information.

    --output table
        Produce human-readable table output. This is the default.

    --output ndjson
        Produce one JSON object per event.

    --asn-dir DIRECTORY
        Load ASN datasets from DIRECTORY instead of the as directory beside
        the executable. Used when -a is enabled.

    --pid PID
        Emit events whose initiating process ID matches PID. May be repeated.

    --uid UID
        Emit events whose initiating user ID matches UID. UID 0 is valid.
        May be repeated.

    --family FAMILY
        Emit events matching ipv4, ipv6, or other. May be repeated.

    --port PORT
        Emit IPv4 or IPv6 events whose destination port matches PORT.
        PORT must be from 1 through 65535. May be repeated.

## System requirements

- Linux
- Linux kernel 5.8 or later, or a vendor kernel with equivalent BPF ring-buffer
  support
- x86-64/amd64 or AArch64/arm64
- privileges required to load and attach eBPF programs

The lifecycle integration suite runs on Ubuntu 24.04 in GitHub Actions and
exercises real IPv4 and IPv6 TCP connections.

## Installation

Release archives are produced for:

- `socket-connect-bpf-linux-amd64.tar.gz`
- `socket-connect-bpf-linux-arm64.tar.gz`

Each archive contains the executable, ASN datasets, documentation, and
licensing files.

Keep the executable and its accompanying `as` directory together when using
ASN enrichment.

### Release verification

Each release includes `SHA256SUMS`.

Verify downloaded archives with:

    sha256sum --check SHA256SUMS

Release archives are created deterministically and the CI verifies archive
members, permissions, ownership, timestamps, paths, gzip metadata, checksums,
and a second reproducible packaging pass.

## Development

Clone the repository and work from the v2 branch:

    git clone https://github.com/ascheriit-dkp/socket-connect-bpf.git
    cd socket-connect-bpf
    git switch v2

Refresh ASN data when required, then build and test:

    ./updateASData.sh
    make all

The build produces amd64 and arm64 binaries under `bin/`.

Run Go tests directly with:

    go test ./...

Run the existing live kernel-filter suite with:

    bash scripts/test-kernel-filters.sh \
      ./bin/amd64/socket-connect-bpf

Run the TCP lifecycle suites with:

    bash scripts/test-tcp-lifecycle.sh \
      ./bin/amd64/socket-connect-bpf

    bash scripts/test-tcp-lifecycle-filters.sh \
      ./bin/amd64/socket-connect-bpf

    bash scripts/test-tcp-lifecycle-table.sh \
      ./bin/amd64/socket-connect-bpf

The live suites require Linux, suitable eBPF privileges through `sudo`, and the
ability to attach the required probes and tracepoint.

### Lifecycle coverage

The lifecycle CI validates real kernel behavior including:

- IPv4 establishment and closure;
- IPv6 establishment and closure;
- refused connections;
- positive errno representation when available;
- local and remote endpoint extraction;
- connect latency and established duration;
- duplicate terminal-event suppression;
- initiating-process enrichment preservation;
- PID, UID, family, and port filtering;
- NDJSON schema version 2;
- lifecycle table output;
- clean shutdown, ring-buffer loss reporting, and lifecycle diagnostics.

The normal Go workflow additionally retains the existing generation, formatting,
unit-test, integration, benchmark, static-analysis, and reproducible release
checks.

## Release artifacts

Build binaries, tests, release archives, `SHA256SUMS`, and verification with:

    make release

Create archives from existing binaries with:

    make release-artifacts

Verify existing release files with:

    make verify-release-artifacts

## Scope and limitations

TCP lifecycle mode is intentionally limited to outbound IPv4 and IPv6 TCP
connections initiated after the tracer attaches.

It does not claim application-layer success and does not currently trace:

- inbound accepted TCP connections;
- listening sockets;
- UDP lifecycles;
- individual packets;
- TCP retransmissions;
- congestion-control state;
- per-packet latency.

See [TCP lifecycle contract](docs/TCP_LIFECYCLE.md) for the detailed semantic
contract and failure/correlation rules.

## License

This repository contains components under different licensing terms.

- The inherited Go code and newly authored v2 Go/userspace code, tests,
  workflows, scripts, and documentation are licensed under the Apache License,
  Version 2.0 unless a file states otherwise.
- The inherited BPF source retains its upstream provenance and kernel-facing
  `Dual MIT/GPL` declaration.
- Vendored headers, Go dependencies, compact kernel headers, and ASN data
  retain their own licensing terms.

See [`LICENSE`](LICENSE), [`LICENSING.md`](LICENSING.md),
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and
[`SECURITY.md`](SECURITY.md).
