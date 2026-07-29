# socket-connect-bpf

socket-connect-bpf is a Linux command line utility that writes human-readable information about each application that makes new network connections to the standard output.

![socket-connect-bpf while making a request with curl](samples/socket-connect-bpf.gif)

More [sample output](samples/socket-connect-bpf-example.txt).

## Details

socket-connect-bpf is a BPF/eBPF prototype with a kernel probe attached to [`security_socket_connect`](https://github.com/torvalds/linux/blob/master/include/linux/security.h). Connections to AF_UNSPEC and AF_UNIX are explicitly excluded.

The following information about each request is displayed when available:

| Name        | Description                                           | Sample             |
|-------------|-------------------------------------------------------|--------------------|
| Time        | Time at which the connection event was received.      | `17:15:58`         |
| AF          | Address family.                                       | `AF_INET`          |
| PID         | Process ID of the process making the request.         | `8549`             |
| Process     | Process path or arguments of the process.             | `/usr/bin/curl`    |
| User        | Username under which the process is executed.         | `root`             |
| Destination | IP address and port of the destination.               | `127.0.0.1 53`     |
| AS-Info     | Autonomous-system information for the IP address.     | `AS36459 (GITHUB)` |

## Use cases

You might want to try `socket-connect-bpf` for the following use cases:

- Check whether an application contains analytics.
- Check whether trusted dependencies communicate with the outside world.
- Use it as a less invasive alternative to kernel modules that provide similar functionality.

## License

This repository contains components under different licensing terms.

- The inherited Go code and newly authored v2 Go/userspace code, tests,
  workflows, and documentation are licensed under the Apache License,
  Version 2.0 unless a file states otherwise.
- The inherited BPF source retains its upstream provenance and its
  kernel-facing `Dual MIT/GPL` declaration.
- Vendored headers, Go dependencies, compact kernel headers, and ASN data
  retain their own licensing terms.

See the following files for complete details:

- [`LICENSE`](LICENSE) — Apache License, Version 2.0.
- [`LICENSING.md`](LICENSING.md) — component-level licensing policy.
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) — provenance,
  attribution, dependency, vendored-header, and external-data notices.

A single licence must not be assumed to apply to every file in this repository.

## System requirements

- x64/amd64 or AArch64/arm64 CPU
- Linux Kernel 4.18 or later

## Installation

### Install binaries

Tested on the following architectures:

- amd64 (Intel x64 CPU)
- arm64 (AWS Graviton2/Arm Neoverse-N1)

Instructions were tested on Debian Bookworm with Linux Kernel 6.5.

Extract the corresponding `socket-connect-bpf-*.tar.gz` release archive.

### Verify binaries

Release verification information will be documented for v2 before stable
release publication.

## Running

Run the tracer with:

    sudo ./socket-connect-bpf

### NDJSON output

Write one JSON object per event:

    sudo ./socket-connect-bpf --output ndjson

The NDJSON schema currently uses schema version `1` and reports
`connect_attempt` events.

### Print all

The `-a` option also prints process arguments and autonomous-system
information:

    sudo ./socket-connect-bpf -a

### Autonomous System information

Autonomous-system information is not displayed by default.

Enable it with:

    sudo ./socket-connect-bpf -a

#### AS data

AS data from [IPtoASN](https://iptoasn.com/) is used.

The local autonomous-system lookup requires additional memory.

To update the AS data while developing, run:

    ./updateASData.sh

## Development

### Build from the repository

The following example uses Debian Bookworm with Linux Kernel 6.5:

    # Install Go 1.23 or later.
    sudo snap install --classic go

    # Install Clang 16.
    sudo apt install clang-16

    # Clone the v2 fork.
    git clone https://github.com/ascheriit-dkp/socket-connect-bpf.git

    cd socket-connect-bpf
    git switch v2

    make all

### Tests

Run the complete generation, build, and test process:

    make all

Run only the Go tests:

    go test ./...

### IDE

[VS Code](https://code.visualstudio.com/) or another Go-compatible IDE can be
used for development.
