# TCP lifecycle contract

## Status

This document defines the semantic and compatibility contract for accurate TCP
lifecycle tracking in socket-connect-bpf v2.

The implementation may evolve, but emitted events must continue to respect the
meanings defined here.

## Purpose

The existing tracer observes outbound socket connection attempts at
`security_socket_connect`.

That observation proves that a process attempted to connect. It does not prove
that a TCP handshake completed successfully.

TCP lifecycle tracking adds explicit observations for:

- Connection attempts.
- Successful TCP establishment.
- Immediate connection failures.
- Asynchronous connection failures.
- TCP connection closure.
- Connection latency.
- Established-connection duration.
- Local and remote TCP endpoints.

## Scope

The initial lifecycle implementation covers outbound IPv4 and IPv6 TCP
connections initiated by local processes.

It does not cover:

- Inbound accepted TCP connections.
- Listening sockets.
- Individual packets.
- TCP retransmission events.
- Congestion-control state.
- Per-packet latency.
- Application-protocol success.
- UDP activity.
- Connections that occur before the tracer is attached.

UDP visibility remains a separate implementation phase because UDP does not
have a TCP-style connection lifecycle.

## Guiding principle

Each event describes only what the tracer has directly observed.

The tracer must not infer successful establishment from the existence of a
connection attempt.

It must not report an application request as successful merely because the TCP
connection was established.

## Public event model

Lifecycle mode defines four public event types.

### `connect_attempt`

A process requested an outbound connection.

This event proves:

- A connection operation reached the observed kernel hook.
- The process identity and remote endpoint were available at that point.

This event does not prove:

- That routing succeeded.
- That the remote host was reachable.
- That a TCP SYN was transmitted.
- That the remote peer accepted the connection.
- That the TCP handshake completed.

### `tcp_established`

The kernel observed the outbound TCP socket entering the established state.

This event proves:

- The TCP connection reached the established state.
- The local and remote tuple associated with that socket was observed.
- The connection can be correlated with an earlier tracked attempt.

This event does not prove:

- That an application-layer request succeeded.
- That data was exchanged.
- That the remote application behaved correctly.

### `tcp_connect_failed`

A tracked outbound TCP attempt reached a terminal failure before successful
establishment.

The failure may be observed through:

- The return value of the initiating connection system call.
- A TCP state transition.
- A socket error associated with a terminal transition.

The event must identify the failure source.

An errno value is included only when the kernel exposes a reliable value.

Absence of an errno must not be represented as errno zero, because zero means
success.

### `tcp_closed`

A previously established tracked TCP connection reached a terminal closed
state.

This event proves:

- The tracer observed the socket reaching the terminal closed state.
- The connection had previously been observed as established.

This event does not necessarily prove:

- Which endpoint initiated closure.
- Whether all application data was delivered.
- Whether closure was graceful.

## Connection identity

All events belonging to one tracked attempt use the same opaque
`connection_id`.

The public identifier must not expose:

- A kernel pointer.
- A userspace pointer.
- A kernel address.
- Information that weakens kernel address-space randomization.

The identifier is scoped to one tracer execution.

Consumers must not assume that it remains stable across tracer restarts.

## TCP tuple

Lifecycle events expose a TCP tuple when the required information is available.

The tuple contains:

- Address family.
- Protocol.
- Local IP address.
- Local port.
- Remote IP address.
- Remote port.

The attempt event may omit the local address or local port when the kernel has
not assigned them yet.

Established and closed events should include the complete tuple whenever it was
observed.

An unavailable value must be omitted rather than fabricated.

## Timing semantics

All lifecycle timing begins with the monotonic kernel timestamp captured for
the tracked attempt.

### Connect latency

For `tcp_established`:

    connect_latency = established_timestamp - attempt_timestamp

For `tcp_connect_failed`:

    connect_latency = failure_timestamp - attempt_timestamp

The failure latency describes how long the tracked attempt remained unresolved.
It is not a network round-trip-time measurement.

### Connection duration

For `tcp_closed`:

    connection_duration = closed_timestamp - established_timestamp

Connection duration is emitted only when both timestamps were observed for the
same tracked socket.

### Wall-clock time

Public output may also include userspace wall-clock observation time.

Monotonic durations must be calculated from kernel timestamps rather than from
userspace wall-clock time.

## Immediate and asynchronous results

TCP connection results may be immediate or asynchronous.

### Immediate success

A successful blocking connection system call may return zero after the socket
has reached an established state.

The implementation must suppress duplicate success events when both a system
call return and a TCP state transition describe the same establishment.

### Immediate failure

A negative terminal connection return value may produce
`tcp_connect_failed`.

Examples include failures detected before an asynchronous handshake remains
pending.

### Pending asynchronous connection

A non-blocking connection may return a pending result such as
`EINPROGRESS`.

A pending result is not a failure event.

The tracer must continue tracking the socket until it observes:

- Successful establishment.
- A terminal failure.
- Closure.
- Eviction from a bounded correlation map.

### Asynchronous failure

A socket that leaves a connecting state without reaching established may
produce `tcp_connect_failed`.

The implementation should include a socket errno when a reliable value is
available.

## Duplicate suppression

Each tracked connection may emit at most:

- One `connect_attempt`.
- One `tcp_established` or one `tcp_connect_failed`.
- One `tcp_closed` after establishment.

A connection must never emit both `tcp_established` and
`tcp_connect_failed`.

Repeated observations of the same terminal state must not produce duplicate
public events.

## Correlation architecture

The implementation uses bounded eBPF maps to correlate process, system-call and
TCP-state observations.

The initial architecture should maintain the following maps.

### Pending operation map

A bounded map keyed by the current process and thread identity.

It associates an active connection operation with its tracked socket and
attempt metadata.

This map supports correlation with the return from the initiating connection
system call.

### TCP connection map

A bounded map keyed by an internal socket correlation key.

It stores the state required for later lifecycle observations, including:

- Opaque connection identifier.
- Attempt timestamp.
- Established timestamp when available.
- Process identity.
- User identity.
- Address family.
- Remote endpoint observed at attempt time.
- Latest complete local and remote tuple.
- Whether establishment has already been emitted.
- Whether a failure has already been emitted.
- Whether closure has already been emitted.

### Map bounds

Correlation maps must have explicit maximum sizes.

A map must not grow without a fixed upper bound.

An LRU map may be used where automatic bounded eviction is appropriate.

## Correlation failures

Lifecycle observations can occur without a matching tracked attempt.

Examples include:

- The tracer attached after the connection began.
- A correlation entry was evicted.
- A hook was unavailable.
- A kernel event was lost.
- The socket was created by an unsupported path.

Unmatched observations must not be presented as fully attributed lifecycle
events.

The implementation must maintain diagnostic counters for meaningful
correlation failures.

At minimum, diagnostics should distinguish:

- Ring-buffer submission failures.
- Correlation-map update failures.
- Missing attempt correlation.
- Correlation eviction or capacity pressure where observable.
- Unsupported lifecycle observations.

## Kernel event stream

The existing shared ring buffer remains the only kernel-to-userspace event
stream.

Lifecycle support must not introduce one independent ring buffer for each event
type.

The internal event ABI must be versioned.

Adding lifecycle fields or event types requires a new internal ABI version
rather than silently changing the layout of ABI version 1.

The internal ABI may use one fixed-size event record with fields interpreted
according to its event type.

Userspace must reject:

- Unsupported ABI versions.
- Unsupported event types.
- Invalid address lengths.
- Invalid protocol values.
- Impossible event-state combinations.
- Records with unexpected binary sizes.

## Kernel filtering

Existing PID, UID, address-family and destination-port filters apply to the
initial connection attempt.

Only attempts accepted by those filters should create lifecycle correlation
state.

Later lifecycle events inherit that decision.

Filters must not be reinterpreted using a process that happens to own or close
the socket later.

This preserves the identity and filter decision associated with the initiating
attempt.

## Lifecycle collection switch

Lifecycle tracking is introduced behind:

    --tcp-lifecycle

Without this option:

- Existing connection-attempt behavior remains unchanged.
- Existing table output remains unchanged.
- Existing NDJSON schema version 1 remains unchanged.
- Lifecycle correlation maps should remain unused where practical.
- Additional lifecycle events are not emitted.

With this option:

- TCP attempts are correlated with later results.
- TCP establishment and failure events are emitted.
- TCP closure is tracked after establishment.
- Lifecycle timing and tuple fields are enabled.

## Table-output compatibility

The existing table format remains unchanged when lifecycle mode is disabled.

Lifecycle mode may use a dedicated table layout containing fields such as:

- Time.
- Event.
- Protocol.
- PID.
- Process.
- Local endpoint.
- Remote endpoint.
- Result.
- Error.
- Connect latency.
- Connection duration.

The lifecycle table must continue to sanitize untrusted process data before
printing it to a terminal.

## NDJSON compatibility

NDJSON schema version 1 remains frozen for the existing attempt-only stream.

It continues to emit only:

    connect_attempt

Lifecycle NDJSON uses schema version 2.

A lifecycle-enabled NDJSON stream must not mix schema version 1 and schema
version 2 records.

Enabling `--tcp-lifecycle` with NDJSON output is an explicit request for the
schema version 2 lifecycle stream.

Schema version 2 must be documented before lifecycle NDJSON is considered
stable.

## NDJSON schema version 2 direction

Each schema version 2 event should contain:

- `schema_version`
- `event_type`
- `connection_id`
- `observed_at`
- `kernel_timestamp_ns`
- `protocol`
- `address_family`
- `process`
- `local`
- `remote`

Result events may additionally contain:

- `result`
- `errno`
- `error`
- `failure_source`
- `connect_latency_ns`

Closure events may additionally contain:

- `connection_duration_ns`

Optional values must use omission rather than ambiguous zero values when zero
could represent a valid result.

## Error representation

Kernel errno values are represented as positive errno numbers in public
output.

For example:

    {
      "errno": 111,
      "error": "connection refused"
    }

The implementation may receive a negative kernel or system-call return value,
but public output normalizes it to the positive errno number.

Unknown errors omit both fields.

## Process attribution

The lifecycle is attributed to the process that initiated the tracked
connection attempt.

Later state changes may execute in a different kernel or process context.

The tracer must not replace the initiating process identity with whichever
task happened to trigger a later state transition.

Improved short-lived-process attribution remains part of the following process
attribution phase.

## Security and privacy

The implementation must not expose raw kernel socket addresses or pointers.

Process arguments remain optional and follow the existing `-a` behavior.

All table fields derived from process data must continue to be terminal-safe.

Structured output must continue to use proper JSON encoding.

Lifecycle diagnostics must not leak kernel addresses.

## Performance requirements

Lifecycle tracking adds work only for TCP attempts accepted by active filters.

Correlation maps must remain bounded.

The implementation should avoid repeated process enrichment for every state
transition.

Benchmarks must compare:

- Attempt-only mode.
- Lifecycle mode.
- Filtered lifecycle mode.
- Table encoding.
- NDJSON schema version 2 encoding.

Performance documentation must state the benchmark environment and command.

## Integration testing

Live integration tests must cover at least:

- Successful IPv4 TCP connection.
- Successful IPv6 TCP connection.
- Connection refused.
- Non-blocking asynchronous connection.
- Established connection followed by closure.
- Connect-latency calculation.
- Connection-duration calculation.
- Complete tuple extraction.
- PID filtering.
- UID filtering.
- Address-family filtering.
- Destination-port filtering.
- Table lifecycle output.
- NDJSON schema version 2 lifecycle output.
- Duplicate suppression.
- Clean shutdown.
- Event-loss summary.
- Correlation diagnostics.

Tests must not assume that every network failure produces the same errno on
every environment.

## Implementation sequence

The implementation should proceed in the following order:

1. Define the internal lifecycle event model and userspace validation.
2. Introduce internal ABI version 2 without changing default public behavior.
3. Add bounded TCP correlation maps.
4. Attach the required TCP and system-call observations.
5. Emit successful and failed connection results.
6. Add closure tracking and durations.
7. Add lifecycle table output.
8. Define and test NDJSON schema version 2.
9. Add live lifecycle integration tests.
10. Add benchmarks and user documentation.

Each step must keep the repository buildable and testable.

## Compatibility policy

The following contracts remain stable throughout this work:

- `master` is not modified by the v2 development branch.
- Attempt-only behavior remains available.
- NDJSON schema version 1 remains valid.
- Existing kernel filters retain their documented semantics.
- Existing amd64 and arm64 builds remain supported.
- The shared ring-buffer architecture remains in place.
- Existing release-artifact verification remains active.

Any deliberate breaking change requires explicit documentation and a versioned
replacement.

## Completion criteria

TCP lifecycle phase 3 is complete only when the tracer can reliably:

- Emit the initial attempt.
- Distinguish establishment from failure.
- Capture immediate failures.
- Capture asynchronous failures.
- Measure connection latency.
- Emit closure after establishment.
- Measure established duration.
- Report the complete tuple when available.
- Preserve initiating-process attribution.
- Avoid duplicate terminal events.
- Preserve NDJSON schema version 1 compatibility.
- Provide a documented NDJSON schema version 2.
- Pass real IPv4 and IPv6 integration tests.
- Report correlation and event-loss limitations honestly.
