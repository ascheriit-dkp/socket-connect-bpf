# socket-connect-bpf v2 design

## Status

This document defines the initial direction for socket-connect-bpf v2.

The design may evolve as implementation work and benchmarks reveal better approaches.

## Mission

Build the best lightweight Linux command-line tool for attributing outbound network activity to processes.

The tool should remain:

* Small and understandable.
* Distributed as a standalone binary.
* Fast enough for busy systems.
* Accurate about what each event proves.
* Useful to both humans and automation.
* Independent from a daemon, GUI, database, or Kubernetes platform.

## Primary use cases

* Investigating unexpected outbound connections.
* Identifying which process contacted a destination.
* Debugging failed or slow TCP connections.
* Observing short-lived processes that access the network.
* Inspecting TCP and UDP activity without full packet capture.
* Running network-behaviour checks in CI environments.
* Producing structured events for scripts and security tooling.

## Initial v2 goals

### Event correctness

Distinguish clearly between:

* Connection attempts.
* Successful TCP connections.
* Failed TCP connections.
* TCP connection closure.
* Connected UDP activity.
* Unconnected UDP sends.

The tool must not describe an attempted connection as successful unless success has been observed.

### Process attribution

Provide, when available:

* PID and TGID.
* UID and GID.
* Executable path.
* Process arguments.
* Parent process identity.
* Process start identity or timestamp.
* Cgroup and namespace identifiers.
* Container metadata where practical.

Process information should remain available for short-lived processes whenever possible.

### Network information

Provide:

* Protocol.
* Address family.
* Local address and port.
* Remote address and port.
* Connection result and error code.
* TCP connection latency.
* Connection duration where available.
* Optional DNS correlation.
* Optional offline ASN enrichment.

### Output

Support:

* Human-readable table output.
* JSON output.
* NDJSON output.
* A documented and versioned event schema.
* Safe escaping of untrusted process data.
* Optional argument capture and redaction.

### Performance

Use:

* Go for userspace.
* `cilium/ebpf` for eBPF integration.
* A shared BPF ring buffer.
* Kernel-side filtering.
* Bounded userspace caches.
* Explicit event-loss reporting.

Performance claims must be supported by reproducible benchmarks.

## Non-goals

V2 will not attempt to become:

* A full packet-capture replacement.
* A desktop application firewall.
* A graphical application.
* A Kubernetes security platform.
* A malware-detection engine.
* A general-purpose system-call tracer.
* A long-term event database.
* A policy-enforcement framework.

These capabilities should be handled through integrations or separate projects.

## Planned implementation phases

### Phase 1 — Stabilise the existing tool

* Fix signal and shutdown handling.
* Fix all event-reader loops.
* Add safe output escaping.
* Add JSON and NDJSON output.
* Add event-loss statistics.
* Add integration tests.
* Clarify licensing and third-party notices.
* Establish baseline benchmarks.

### Phase 2 — Replace the event pipeline

* Introduce a single typed ring-buffer stream.
* Add kernel timestamps.
* Add kernel-side filters.
* Redesign event structures.
* Preserve compatibility with amd64 and arm64.
* Document the event schema.

### Phase 3 — Add accurate TCP lifecycle tracking

* Track connection attempts.
* Detect successful establishment.
* Capture immediate and asynchronous failures.
* Measure connect latency.
* Track connection closure and duration.
* Include the complete local and remote tuple.

### Phase 4 — Improve process attribution

* Observe process execution and exit.
* Maintain a bounded process cache.
* Preserve information for short-lived processes.
* Add parent-process, cgroup and namespace context.
* Add optional container enrichment.

### Phase 5 — Expand UDP visibility

* Preserve connected UDP observation.
* Observe unconnected `sendto` and `sendmsg` destinations.
* Report UDP semantics without pretending that UDP has a TCP-style connection lifecycle.
* Add protocol-specific tests and benchmarks.

### Phase 6 — Add optional enrichment

* DNS correlation with confidence metadata.
* Efficient IPv4 and IPv6 ASN lookup.
* Configurable enrichment databases.
* Argument redaction.
* Export and integration examples.

## Quality requirements

Every major feature should include:

* Unit tests where applicable.
* Integration tests using real network operations.
* Documentation explaining its semantics.
* Performance measurements.
* Failure and event-loss behaviour.
* Compatibility considerations.
* Privacy and security considerations.

## Licensing direction

The project currently contains components under different licences.

V2 should:

* Preserve all required attribution.
* Keep licence notices with inherited files.
* Add SPDX identifiers to project source files.
* Clearly separate userspace, BPF, vendored and data licences.
* Maintain a `THIRD_PARTY_NOTICES` document.
* Avoid copying competitor implementations unless their licence obligations have been reviewed.

## Guiding principle

Prefer a small number of accurate, well-defined events over a large number of ambiguous or noisy events.

The project succeeds when users can trust what an event means without deploying a complete observability platform.
