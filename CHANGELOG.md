# Changelog

All notable project changes are documented here.

## 2.0.0

### Added

- outbound IPv4 and IPv6 TCP lifecycle tracking from attempt through establishment, failure, and closure;
- opaque per-run `connection_id` correlation, connect latency, connection duration, errno and failure-source reporting;
- schema version 2 NDJSON for TCP lifecycle events;
- outbound UDP `sendto` and `sendmsg` destination visibility with schema version 3 NDJSON;
- kernel-side PID, UID, address-family, and destination-port filters;
- process exec/exit observation with bounded PID-generation-aware attribution;
- process GID, start identity, parent, cgroup, namespace, and best-effort container metadata;
- optional offline IPv4 and IPv6 ASN enrichment;
- optional DNS observation correlation with source and confidence metadata;
- configurable process-argument redaction before cached enrichment is retained;
- tested NDJSON export, CSV, CI-gate, and DNS-input integration examples;
- deterministic amd64 and arm64 release archives with `SHA256SUMS` and strict archive verification;
- live Linux integration suites and reproducible output benchmarks.

### Changed

- event transport uses bounded typed ring-buffer pipelines with explicit loss diagnostics;
- structured output is versioned and documents what each event proves;
- TCP lifecycle filtering is decided at the initiating attempt and preserved for later correlated events;
- release archives include documentation, licensing files, ASN datasets, and tested integration examples.

### Compatibility

- compatibility mode remains attempt-only and keeps NDJSON schema version 1;
- `--tcp-lifecycle` selects schema version 2;
- `--udp` selects schema version 3;
- a single NDJSON stream does not mix these schema versions.

### Scope

Version 2.0.0 remains focused on outbound process-aware network visibility. It does not claim inbound TCP accept visibility, packet capture, UDP delivery success, retransmission telemetry, congestion state, or per-packet latency.
