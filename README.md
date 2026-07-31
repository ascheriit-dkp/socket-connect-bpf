# socket-connect-bpf

socket-connect-bpf is a lightweight Linux command-line utility that records
process-aware outbound socket connection attempts using eBPF.

It can produce either a human-readable table or newline-delimited JSON
(NDJSON).

![socket-connect-bpf while making a request with curl](samples/socket-connect-bpf.gif)

See additional [sample output](samples/socket-connect-bpf-example.txt).

## Details

socket-connect-bpf attaches an eBPF kernel probe to
[`security_socket_connect`](https://github.com/torvalds/linux/blob/master/include/linux/security.h).

Each emitted event represents a connection attempt observed at that hook. It
does not prove that the connection later succeeded.

Connections using `AF_UNSPEC` and `AF_UNIX` are explicitly excluded.

Kernel events use a fixed internal ABI and are delivered to userspace through
one shared BPF ring buffer. IPv4, IPv6, and supported non-IP address families
therefore use the same event stream and decoder.

Optional PID, UID, address-family, and destination-port filters are evaluated
inside the eBPF program before matching events are submitted to the ring
buffer. This reduces ring-buffer traffic and avoids unnecessary userspace
enrichment for rejected events.

Each internal event includes a monotonic kernel timestamp. The public NDJSON
schema version 1 continues to expose `observed_at` as the userspace observation
time for compatibility.

The following information is reported when available:

| Name        | Description                                      | Sample             |
|-------------|--------------------------------------------------|--------------------|
| Time        | Time at which the event was received.            | `17:15:58`         |
| AF          | Address family.                                  | `AF_INET`          |
| PID         | Process ID that attempted the connection.        | `8549`             |
| Process     | Process path or command-line arguments.          | `/usr/bin/curl`    |
| User        | User running the process.                        | `root`             |
| Destination | Destination IP address and port.                 | `127.0.0.1 53`     |
| AS-Info     | Autonomous-system information for the address.   | `AS36459 (GITHUB)` |

## Use cases

socket-connect-bpf can help with tasks such as:

- Identifying unexpected outbound communication.
- Checking whether an application contains analytics or telemetry.
- Observing network activity from trusted dependencies.
- Investigating which process attempted a particular connection.
- Feeding process-aware connection events into scripts or log pipelines.
- Limiting collection to selected processes, users, address families, or
  destination ports.

## System requirements

- Linux
- Linux kernel 5.8 or later, or a vendor kernel with equivalent BPF ring-buffer
  support
- x86-64/amd64 or AArch64/arm64 CPU
- Root privileges or equivalent permissions for loading and attaching eBPF
  programs

## Installation

### Release archive

Download and extract the archive matching the target architecture:

- `socket-connect-bpf-linux-amd64.tar.gz`
- `socket-connect-bpf-linux-arm64.tar.gz`

The extracted directory contains:

- `socket-connect-bpf`
- `as/ip2asn-v4-u32.tsv`
- `as/ip2asn-v6.tsv`
- `README.md`
- `LICENSE`
- `LICENSING.md`
- `THIRD_PARTY_NOTICES.md`

Keep the executable and its accompanying `as` directory together when using
autonomous-system enrichment.

### Release verification

Release verification information will be documented before the stable v2
release is published.

## Running

Run the tracer with human-readable table output:

    sudo ./socket-connect-bpf

The default output does not include process arguments or autonomous-system
information.

Running without any filter options preserves the unfiltered behavior.

### Kernel-side filtering

Connection-attempt events can be filtered by:

- Process ID with `--pid`.
- User ID with `--uid`.
- Address-family category with `--family`.
- Destination port with `--port`.

Each filter option may be specified more than once.

Filter one process:

    sudo ./socket-connect-bpf --pid 1234

Filter connections from UID `1000`:

    sudo ./socket-connect-bpf --uid 1000

Filter IPv4 connections:

    sudo ./socket-connect-bpf --family ipv4

Filter HTTPS destination ports:

    sudo ./socket-connect-bpf --port 443

Combine several categories:

    sudo ./socket-connect-bpf \
      --uid 1000 \
      --family ipv4 \
      --port 80 \
      --port 443

Values within the same category use OR semantics. For example:

    sudo ./socket-connect-bpf \
      --pid 1234 \
      --pid 5678

matches either PID `1234` or PID `5678`.

Different categories use AND semantics. For example:

    sudo ./socket-connect-bpf \
      --uid 1000 \
      --port 443

matches only events whose UID is `1000` and whose destination port is `443`.

The supported address-family values are:

| Value   | Matching events                                      |
|---------|------------------------------------------------------|
| `ipv4`  | `AF_INET` events                                     |
| `ipv6`  | `AF_INET6` events                                    |
| `other` | Supported non-IP families other than UNIX/UNSPEC     |

Address-family values are case-sensitive.

When a destination-port filter is active, supported non-IP events do not
match because they do not contain a destination port.

Duplicate values are accepted and treated as one value.

The initial implementation supports at most 1024 distinct PID values, 1024
distinct UID values, and 1024 distinct destination-port values.

Invalid filter values cause startup to fail before the eBPF probe is attached.

The complete behavior and compatibility contract is documented in
[Kernel-side filter contract](docs/KERNEL_FILTERS.md).

### NDJSON output

Write one JSON object per event:

    sudo ./socket-connect-bpf --output ndjson

Filters can be combined with NDJSON output:

    sudo ./socket-connect-bpf \
      --family ipv6 \
      --port 443 \
      --output ndjson

The NDJSON schema currently uses schema version `1` and reports
`connect_attempt` events.

Filtering does not alter the event structure or NDJSON schema.

The public compatibility contract is documented in
[NDJSON Event Schema v1](docs/EVENT_SCHEMA_V1.md).

Diagnostics and errors are written to standard error rather than mixed into
the NDJSON stream.

### Extended information

Use `-a` to include process arguments and autonomous-system information:

    sudo ./socket-connect-bpf -a

The option can also be combined with NDJSON output and filters:

    sudo ./socket-connect-bpf \
      -a \
      --uid 1000 \
      --output ndjson

### Event-loss reporting

The BPF program counts events that matched all configured filters but could not
be submitted because the shared ring buffer had no available space.

Events intentionally rejected by filters are not counted as lost events.

When the tracer shuts down, it writes a summary to standard error:

    ring-buffer event loss summary: total=0

A non-zero value means matching connection attempts were observed by the probe
but could not be delivered to userspace.

## Autonomous-system data

Autonomous-system enrichment uses datasets from
[IPtoASN](https://iptoasn.com/).

ASN datasets are loaded only when `-a` is enabled.

### Default dataset location

By default, socket-connect-bpf loads the following directory beside the real
executable:

    as/

This means the tracer can be launched from any working directory as long as
the release layout remains intact:

    package/
    ├── socket-connect-bpf
    └── as/
        ├── ip2asn-v4-u32.tsv
        └── ip2asn-v6.tsv

Symbolic links to the executable are resolved before locating the default
dataset directory.

### Custom dataset location

Override the default directory with `--asn-dir`:

    sudo ./socket-connect-bpf \
      -a \
      --asn-dir /var/lib/socket-connect-bpf/as

Relative paths supplied through `--asn-dir` are resolved from the current
working directory.

The specified directory must contain:

    ip2asn-v4-u32.tsv
    ip2asn-v6.tsv

When `-a` is enabled, missing or malformed ASN datasets cause startup to fail
with a descriptive error. Running without `-a` does not require the datasets.

### Updating datasets

To download current datasets while developing from the repository:

    ./updateASData.sh

Local ASN lookup requires additional memory, especially for the IPv6 dataset.

## Command-line options

    -a
        Include process arguments and autonomous-system information.

    --output table
        Produce human-readable table output. This is the default.

    --output ndjson
        Produce one JSON object per event.

    --asn-dir DIRECTORY
        Load ASN datasets from DIRECTORY instead of the as directory beside
        the executable. This option is used when -a is enabled.

    --pid PID
        Emit events whose process ID matches PID. PID must be an unsigned
        decimal value greater than zero. May be repeated.

    --uid UID
        Emit events whose user ID matches UID. UID must be an unsigned decimal
        value. UID 0 is valid. May be repeated.

    --family FAMILY
        Emit events matching FAMILY. Supported values are ipv4, ipv6 and
        other. Values are case-sensitive. May be repeated.

    --port PORT
        Emit IPv4 or IPv6 events whose destination port matches PORT. PORT
        must be from 1 through 65535. May be repeated.

## Development

### Build from the repository

The following example uses Debian Bookworm with Linux kernel 6.5:

    # Install Go 1.23 or later.
    sudo snap install --classic go

    # Install Clang 16.
    sudo apt install clang-16

    # Clone the fork.
    git clone https://github.com/ascheriit-dkp/socket-connect-bpf.git

    cd socket-connect-bpf
    git switch v2

    make all

The build produces binaries for amd64 and arm64 under `bin/`.

### Tests

Run generation, builds, and all Go tests:

    make all

Run only the Go tests:

    go test ./...

Run the live kernel-filter integration suite after building:

    bash scripts/test-kernel-filters.sh \
      ./bin/amd64/socket-connect-bpf

The live integration suite requires Linux, root privileges through `sudo`, and
the ability to attach the eBPF probe.

GitHub Actions additionally performs:

- Real unfiltered table-output tracing.
- Real unfiltered NDJSON tracing and schema validation.
- Live PID, UID, address-family, and destination-port filtering tests.
- OR-semantics and AND-semantics filter tests.
- Filtered table and NDJSON exclusion checks.
- NDJSON schema v1 contract tests.
- Event-loss summary validation.
- Release archive content verification.
- Packaged ASN loading from an unrelated working directory.

## License

This repository contains components under different licensing terms.

- The inherited Go code and newly authored v2 Go/userspace code, tests,
  workflows, scripts, and documentation are licensed under the Apache License,
  Version 2.0 unless a file states otherwise.
- The inherited BPF source retains its upstream provenance and its
  kernel-facing `Dual MIT/GPL` declaration.
- Vendored headers, Go dependencies, compact kernel headers, and ASN data
  retain their own licensing terms.

See:

- [`LICENSE`](LICENSE) — Apache License, Version 2.0.
- [`LICENSING.md`](LICENSING.md) — component-level licensing policy.
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) — provenance,
  attribution, dependency, vendored-header, and external-data notices.

A single licence must not be assumed to apply to every file in this repository.
