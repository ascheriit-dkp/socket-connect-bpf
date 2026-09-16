# socket-connect-bpf

socket-connect-bpf is a lightweight Linux command-line tracer for
process-aware outbound socket activity using eBPF.

It supports three collection modes:

- the compatibility mode, which reports outbound connection attempts exactly as
  the existing v2 interface does;
- TCP lifecycle mode, enabled explicitly with `--tcp-lifecycle`, which follows
  outbound IPv4 and IPv6 TCP connections from attempt through establishment,
  failure, and closure;
- UDP visibility mode, enabled explicitly with `--udp`, which reports outbound
  IPv4 and IPv6 UDP sends that carry an explicit per-datagram destination.

All modes can produce a human-readable table or newline-delimited JSON
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

## UDP visibility mode

Enable per-datagram UDP destination observation with:

    sudo ./socket-connect-bpf --udp

UDP mode emits `udp_send` for outbound IPv4 and IPv6 UDP sends with an explicit
destination supplied through the `sendto` or `sendmsg` path.

An `udp_send` event means only that the kernel observed the send and its
explicit destination. It does not prove delivery, reachability, receipt, or
application-layer success, and it does not invent a TCP-style UDP lifecycle.

Use UDP NDJSON with:

    sudo ./socket-connect-bpf \
      --udp \
      --output ndjson

UDP NDJSON uses schema version `3`. See
[NDJSON Event Schema v3](docs/EVENT_SCHEMA_V3.md) for the complete contract.

Connected UDP destination observation through `connect()` remains available in
the compatibility collection path. `--udp` adds visibility for unconnected
per-datagram destinations.

`--udp` and `--tcp-lifecycle` are intentionally mutually exclusive so a single
NDJSON stream never mixes schema version 2 and schema version 3 records.

### Compatibility

Without `--tcp-lifecycle` or `--udp`, existing behavior is unchanged:

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

### UDP table

    sudo ./socket-connect-bpf \
      --udp \
      --output table

The UDP table reports observation time, event type, process, address family,
and explicit remote UDP endpoint.

### Attempt-only NDJSON

    sudo ./socket-connect-bpf --output ndjson

This emits schema version `1` and `connect_attempt` events only.

### Lifecycle NDJSON

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --output ndjson

This emits schema version `2` and never mixes version 1 and version 2 records in
the same stream.

### UDP NDJSON

    sudo ./socket-connect-bpf \
      --udp \
      --output ndjson

This emits schema version `3` and `udp_send` records only.

Diagnostics and errors are written to standard error rather than mixed into the
NDJSON stream.

## Extended information

Use `-a` to include additional process information and autonomous-system
metadata:

    sudo ./socket-connect-bpf -a

It can be combined with TCP lifecycle mode or UDP mode:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      -a \
      --output ndjson

    sudo ./socket-connect-bpf \
      --udp \
      -a \
      --output ndjson

Lifecycle mode caches initiating-process enrichment by `connection_id` after an
attempt. TCP lifecycle and UDP modes also use a bounded process-generation
cache populated by process execution and exit observations.

### Process attribution

Advanced TCP and UDP modes observe process execution and exit and keep a
bounded cache of process generations. This prevents a later process that reuses
the same PID from being silently substituted for the process that initiated a
tracked network operation.

Structured TCP and UDP output exposes additional process context when
available:

- real GID;
- process start identity;
- parent PID and parent start identity;
- kernel cgroup ID and cgroup path;
- cgroup, IPC, mount, network, PID, user, and UTS namespace inode IDs;
- best-effort Docker, containerd, CRI-O, or Podman identity derived from the
  cgroup path.

Container metadata is deliberately best effort. The tracer does not contact a
container runtime, Docker daemon, or Kubernetes API. Advanced metadata that
exists only in `/proc` can be absent for a process that exits before userspace
can snapshot it. See [NDJSON Event Schema v2](docs/EVENT_SCHEMA_V2.md) and
[NDJSON Event Schema v3](docs/EVENT_SCHEMA_V3.md) for the exact optional fields
and semantics.

### DNS correlation

Optional DNS correlation is loaded from user-supplied JSONL observations:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --output ndjson \
      --dns-observations /path/to/dns-observations.jsonl

The flag may be repeated. The tracer does not perform PTR or other DNS network
lookups itself.

TCP lifecycle schema v2 and UDP schema v3 may emit an optional `dns` object with
the correlated name, source, confidence, observation time, and expiry. A
PID-specific observation is higher confidence than a process-agnostic IP
observation. Expired, future, and PID-mismatched observations are ignored.

DNS metadata is correlation, not proof that a network event was caused by a DNS
response. See [DNS correlation](docs/DNS_CORRELATION.md) for the input format
and exact confidence semantics.

### Argument redaction

When `-a` captures process arguments, repeated `--redact-arg` rules can replace
matching text before it is retained in userspace enrichment caches or emitted:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      -a \
      --redact-arg '(?i)(token|password|secret)=[^ ]+' \
      --output ndjson

Rules are Go regular expressions and matching text is replaced with
`[REDACTED]`. Redaction is pattern-based; unmatched sensitive values are not
automatically detected.

The same configured redaction behavior applies to compatibility, TCP lifecycle,
and UDP output. See [Process argument redaction](docs/ARGUMENT_REDACTION.md).

## Export and integrations

NDJSON is the automation interface. Keep event stdout separate from diagnostic
stderr:

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --output ndjson \
      >events.ndjson \
      2>tracer.log

The repository includes tested examples for common integration work:

- `examples/ndjson_to_csv.py`: schema v1/v2/v3 NDJSON to a common CSV view;
- `examples/check_tcp_failures.py`: minimal schema v2 CI failure gate;
- `examples/dns-observations.example.jsonl`: DNS observation input fixture.

Example:

    python3 examples/ndjson_to_csv.py \
      <events.ndjson \
      >events.csv

See [Export and integration examples](docs/EXPORT_INTEGRATIONS.md) for jq,
streaming, CSV, CI, DNS, and redaction examples.

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

TCP lifecycle mode tracks outbound IPv4 and IPv6 TCP connections. UDP mode
reports explicit IPv4 and IPv6 UDP destinations; `--family other` does not
match a schema version 3 UDP event.

For TCP lifecycle, the filter decision is made at the initiating attempt and
later lifecycle events inherit that decision. UDP filters are evaluated before
an accepted UDP send is submitted to its ring buffer.

The complete filter contract is documented in
[Kernel-side filter contract](docs/KERNEL_FILTERS.md).

## Event loss and lifecycle diagnostics

The ring buffers count matching events that could not be submitted because
space was unavailable.

Compatibility/TCP shutdown reports the existing socket-event counter:

    ring-buffer event loss summary: total=0

UDP mode reports:

    UDP event loss summary: total=0

TCP lifecycle mode also reports bounded-correlation diagnostics:

    TCP lifecycle diagnostic summary: map_update_failures=0 missing_correlation=0 unsupported_observations=0

Process exec/exit observation in advanced modes has its own loss counter:

    process event loss summary: total=0

Non-zero diagnostic values indicate that one or more observations could not be
represented reliably. They are diagnostics, not fabricated network events.

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
        and closure. Lifecycle NDJSON uses schema version 2. Cannot be combined
        with --udp.

    --udp
        Observe outbound IPv4 and IPv6 UDP sends with explicit per-datagram
        destinations. UDP NDJSON uses schema version 3. Cannot be combined with
        --tcp-lifecycle.

    -a
        Include process arguments and autonomous-system information.

    --output table
        Produce human-readable table output. This is the default.

    --output ndjson
        Produce one JSON object per event.

    --asn-dir DIRECTORY
        Load ASN datasets from DIRECTORY instead of the as directory beside
        the executable. Used when -a is enabled.

    --dns-observations FILE
        Load DNS observation JSONL for optional IP-to-name correlation. May be
        repeated. Does not cause network DNS lookups.

    --redact-arg REGEX
        Replace matching process-argument text with [REDACTED]. May be repeated.
        Applies to arguments captured with -a.

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

The TCP lifecycle and UDP integration suites run on Ubuntu 24.04 in GitHub
Actions and exercise real IPv4 and IPv6 network operations.

## Installation

Release archives are produced for:

- `socket-connect-bpf-linux-amd64.tar.gz`
- `socket-connect-bpf-linux-arm64.tar.gz`

Each archive contains the executable, ASN datasets, documentation, tested
integration examples, and licensing files.

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

Run the export/integration example tests with:

    bash scripts/test-export-examples.sh

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

    bash scripts/test-tcp-lifecycle-async.sh \
      ./bin/amd64/socket-connect-bpf

    bash scripts/test-process-context.sh \
      ./bin/amd64/socket-connect-bpf

    bash scripts/test-argument-redaction.sh \
      ./bin/amd64/socket-connect-bpf

    bash scripts/test-dns-correlation.sh \
      ./bin/amd64/socket-connect-bpf

Run the UDP live suites with:

    bash scripts/test-udp-visibility.sh \
      ./bin/amd64/socket-connect-bpf

    bash scripts/test-udp-filters.sh \
      ./bin/amd64/socket-connect-bpf

The live suites require Linux, suitable eBPF privileges through `sudo`, and the
ability to attach the required probes and tracepoints.

### TCP lifecycle coverage

The lifecycle CI validates real kernel behavior including:

- IPv4 establishment and closure;
- IPv6 establishment and closure;
- refused connections;
- positive errno representation when available;
- local and remote endpoint extraction;
- connect latency and established duration;
- duplicate terminal-event suppression;
- initiating-process enrichment preservation;
- exec/exit process attribution and PID-generation preservation;
- parent, cgroup, namespace, and best-effort container context;
- argument redaction;
- DNS correlation;
- PID, UID, family, and port filtering;
- NDJSON schema version 2;
- lifecycle table output;
- clean shutdown, ring-buffer loss reporting, and lifecycle diagnostics.

### UDP coverage

The UDP CI validates real kernel behavior including:

- explicit IPv4 destinations supplied through `sendto`;
- explicit IPv4 destinations supplied through `sendmsg`;
- IPv6 explicit destinations when IPv6 is available on the runner;
- PID, UID, family, and destination-port filtering;
- NDJSON schema version 3;
- absence of TCP-style success and connection semantics;
- process attribution;
- clean shutdown and UDP event-loss reporting.

The normal Go workflow additionally retains generation, formatting, unit-test,
integration, benchmark, export-example, and reproducible release checks.

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

UDP mode intentionally reports explicit per-datagram destinations rather than a
fictional UDP connection lifecycle. Connected UDP sends without an explicit
`msg_name` are not emitted as `udp_send`; their destination may already have
been observed through the compatibility `connect()` path.

The tracer does not claim application-layer success and does not currently
trace:

- inbound accepted TCP connections;
- listening sockets;
- UDP delivery or receive-side outcomes;
- individual packets;
- TCP retransmissions;
- congestion-control state;
- per-packet latency.

See [TCP lifecycle contract](docs/TCP_LIFECYCLE.md),
[NDJSON Event Schema v2](docs/EVENT_SCHEMA_V2.md),
[NDJSON Event Schema v3](docs/EVENT_SCHEMA_V3.md),
[DNS correlation](docs/DNS_CORRELATION.md),
[Process argument redaction](docs/ARGUMENT_REDACTION.md), and
[Export and integration examples](docs/EXPORT_INTEGRATIONS.md) for detailed
semantics and integration guidance.

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
