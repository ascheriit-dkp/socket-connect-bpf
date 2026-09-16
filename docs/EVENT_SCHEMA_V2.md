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
- `address_family`: `AF_INET` or `AF_INET6` for the current lifecycle mode.
- `process`: initiating process metadata.
- `local`: local endpoint object.
- `remote`: remote endpoint object.

The opaque `connection_id` is for correlation only. It is not a kernel pointer
and must not be assumed stable across tracer restarts.

## Process object

The `process` object always contains:

- `pid`: initiating process ID. In lifecycle mode this is the thread-group ID
  captured at the initiating TCP attempt.
- `uid`: initiating user ID.

It may also contain:

- `gid`: real group ID observed for the process.
- `comm`: task command name when available.
- `executable`: resolved executable path when userspace enrichment succeeds.
- `user`: resolved user name, or the numeric UID when name lookup fails.
- `start_time_ticks`: process start identity from `/proc/<pid>/stat`, measured
  in clock ticks since boot. Together with `pid` it distinguishes PID reuse
  when available.
- `parent`: parent-process identity object.
- `cgroup`: cgroup identity object.
- `namespaces`: Linux namespace inode identifiers.
- `container`: best-effort container runtime identity derived from the cgroup
  path when a supported pattern is recognized.

When `-a` is enabled it may additionally contain:

- `arguments`: command-line arguments captured from the initiating process.

### Parent object

`process.parent` may contain:

- `pid`: parent process ID.
- `start_time_ticks`: parent start identity from `/proc/<ppid>/stat` when the
  parent still exists while enrichment is performed.

### Cgroup object

`process.cgroup` may contain:

- `id`: kernel cgroup ID captured at process execution when available.
- `path`: cgroup path read from `/proc/<pid>/cgroup` when available. Unified
  cgroup v2 is preferred; cgroup v1 falls back to the first usable hierarchy.

### Namespaces object

`process.namespaces` may contain inode identifiers for:

- `cgroup`
- `ipc`
- `mnt`
- `net`
- `pid`
- `user`
- `uts`

Namespace identifiers come from `/proc/<pid>/ns/*`. Missing namespace entries
are omitted rather than fabricated.

### Container object

`process.container` is best-effort metadata and is emitted only when the cgroup
path matches a recognized runtime pattern. It contains:

- `runtime`: currently `docker`, `containerd`, `cri-o`, or `podman`.
- `id`: container ID extracted from the cgroup path.

No container daemon or Kubernetes API is queried. Absence of `container` does
not prove that the process is running directly on the host.

Process execution and exit are observed in lifecycle mode. A bounded process
cache retains multiple PID generations using monotonic execution timestamps.
The connection-level enrichment cache then preserves the selected initiating
process metadata for later establishment, failure, and closure events.

Advanced `/proc` metadata is best effort. Very short-lived processes can still
lose fields that exist only in `/proc` if they exit before userspace snapshots
them; kernel-captured process identifiers remain available.

## ASN object

When `-a` is enabled and the remote address matches the loaded IP-to-ASN data,
a top-level `asn` object may be emitted:

- `number`: autonomous-system number.
- `name`: autonomous-system name when available.

ASN enrichment is optional. Absence of a match is represented by omission of
the `asn` field.

## DNS object

When `--dns` is enabled and reverse lookup of the remote IP succeeds, an
optional top-level `dns` object may be emitted:

- `name`: normalized PTR name returned by the resolver;
- `source`: `reverse_dns`;
- `confidence`: `low`.

This metadata does not prove that the initiating process requested, queried, or
used the returned hostname. It is only a reverse-DNS correlation for the
observed IP at enrichment time. See `DNS_ENRICHMENT.md` for cache, timeout,
privacy, and performance semantics.

## Endpoint objects

Endpoint objects may contain:

- `ip`: textual IPv4 or IPv6 address.
- `port`: numeric TCP port.

An endpoint component that was not observed is omitted. A port that was
observed with the numeric value `0` is emitted as `0`; omission and zero are not
interchangeable.

The remote endpoint is required for valid lifecycle records.

The initial `connect_attempt` may omit the local endpoint because the kernel may
not have selected the final source address and ephemeral port yet.
`tcp_established` and `tcp_closed` include the observed local and remote TCP
tuple when the kernel exposes it through the TCP state tracepoint.

## `connect_attempt`

A `connect_attempt` record reports that the kernel observed an outbound TCP
connection attempt accepted by the active filters.

It does not contain a `result` field because an attempt alone does not imply
success or failure.

Example:

```json
{"schema_version":2,"event_type":"connect_attempt","connection_id":42,"observed_at":"2026-08-26T12:00:00Z","kernel_timestamp_ns":1000,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"gid":1000,"comm":"curl","start_time_ticks":123456,"parent":{"pid":1200,"start_time_ticks":120000},"cgroup":{"id":987,"path":"/user.slice/user-1000.slice/session-2.scope"},"namespaces":{"mnt":4026531841,"net":4026531993,"pid":4026531836}},"local":{},"remote":{"ip":"198.51.100.20","port":443}}
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
{"schema_version":2,"event_type":"tcp_established","connection_id":42,"observed_at":"2026-08-26T12:00:00.001Z","kernel_timestamp_ns":1500,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"curl"},"local":{"ip":"192.0.2.10","port":40000},"remote":{"ip":"198.51.100.20","port":443},"result":"success","connect_latency_ns":500}
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
{"schema_version":2,"event_type":"tcp_closed","connection_id":42,"observed_at":"2026-08-26T12:00:01Z","kernel_timestamp_ns":5000,"protocol":"tcp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"curl"},"local":{"ip":"192.0.2.10","port":40000},"remote":{"ip":"198.51.100.20","port":443},"connection_duration_ns":3500}
```

## Filtering semantics

Existing PID, UID, family, and destination-port filters are evaluated for the
initial connection attempt. Only accepted attempts create lifecycle correlation
state. Later lifecycle events inherit that original decision rather than being
re-filtered in a potentially different execution context.

## Compatibility rules

Consumers should ignore unknown fields so schema version 2 can gain optional
metadata without changing existing field meanings.

A change that alters the meaning or representation of an existing required
field requires a new schema version.

Schema version 1 remains frozen for the attempt-only stream.
