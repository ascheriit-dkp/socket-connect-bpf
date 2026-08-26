# TCP lifecycle NDJSON schema version 2

## Status

Schema version 2 is used only when TCP lifecycle collection is enabled with
`--tcp-lifecycle --output ndjson`.

The existing attempt-only NDJSON schema version 1 remains unchanged when
`--tcp-lifecycle` is not supplied.

A single NDJSON stream never mixes schema versions 1 and 2.

## Common fields

Every schema version 2 record contains:

- `schema_version`: integer `2`.
- `event_type`: one of `connect_attempt`, `tcp_established`,
  `tcp_connect_failed`, or `tcp_closed`.
- `connection_id`: non-zero opaque identifier scoped to one tracer run.
- `observed_at`: userspace UTC observation timestamp in RFC 3339 format.
- `kernel_timestamp_ns`: monotonic kernel timestamp for the event.
- `protocol`: `tcp`.
- `address_family`: address-family name such as `AF_INET` or `AF_INET6`.
- `process`: initiating process metadata.
- `local`: local endpoint object.
- `remote`: remote endpoint object.

The opaque `connection_id` is for correlation only. It is not a kernel pointer
and must not be assumed stable across tracer restarts.

## Process object

The `process` object contains:

- `pid`: initiating process ID.
- `uid`: initiating user ID.
- `comm`: task command name when available.

Additional process-enrichment fields may be added compatibly in the future.

## Endpoint objects

Endpoint objects may contain:

- `ip`: textual IPv4 or IPv6 address.
- `port`: numeric TCP port.

An endpoint component that was not observed is omitted. A port that was
observed with the numeric value `0` is emitted as `0`; omission and zero are not
interchangeable.

The remote endpoint is required for valid lifecycle records. The local endpoint
may be incomplete on an initial attempt and may be omitted when the kernel hook
does not expose it reliably.

## `connect_attempt`

A `connect_attempt` record reports that the kernel observed an outbound TCP
connection attempt accepted by the active filters.

It does not contain a `result` field because an attempt alone does not imply
success or failure.

Example:

```json
{"schema_version":2,"event_type":"connect_attempt","connection_id":42,"observed_at":"2026-08-26T12:00:00Z","kernel_timestamp_ns":1000,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"curl"},"local":{},"remote":{"ip":"198.51.100.20","port":443}}
```

## `tcp_established`

A `tcp_established` record reports that the tracked socket entered the TCP
established state.

Additional fields:

- `result`: `success`.
- `connect_latency_ns`: monotonic duration from the tracked attempt to
  establishment when available.

Example:

```json
{"schema_version":2,"event_type":"tcp_established","connection_id":42,"observed_at":"2026-08-26T12:00:00.001Z","kernel_timestamp_ns":1500,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"curl"},"local":{},"remote":{"ip":"198.51.100.20","port":443},"result":"success","connect_latency_ns":500}
```

## `tcp_connect_failed`

A `tcp_connect_failed` record reports a terminal failure before establishment.

Additional fields:

- `result`: `failed`.
- `failure_source`: `connect_return`, `tcp_state`, or `socket_error`.
- `connect_latency_ns`: monotonic duration from the attempt to the observed
  failure when available.
- `errno`: positive errno number when the kernel supplied a reliable value.
- `error`: textual errno description when `errno` is present.

`errno` and `error` are omitted when no reliable errno was observed. Errno zero
is never used to represent an unknown error.

Example:

```json
{"schema_version":2,"event_type":"tcp_connect_failed","connection_id":42,"observed_at":"2026-08-26T12:00:00.002Z","kernel_timestamp_ns":1750,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"curl"},"local":{},"remote":{"ip":"198.51.100.20","port":443},"result":"failed","failure_source":"connect_return","errno":111,"error":"connection refused","connect_latency_ns":750}
```

## `tcp_closed`

A `tcp_closed` record reports terminal closure for a connection that was
previously observed as established.

Additional field:

- `connection_duration_ns`: monotonic duration from establishment to observed
  closure when available.

Example:

```json
{"schema_version":2,"event_type":"tcp_closed","connection_id":42,"observed_at":"2026-08-26T12:00:01Z","kernel_timestamp_ns":5000,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"curl"},"local":{},"remote":{"ip":"198.51.100.20","port":443},"connection_duration_ns":3500}
```

## Compatibility rules

Consumers should ignore unknown fields so schema version 2 can gain optional
metadata without changing existing field meanings.

A change that alters the meaning or representation of an existing required
field requires a new schema version.

Schema version 1 remains frozen for the attempt-only stream.
