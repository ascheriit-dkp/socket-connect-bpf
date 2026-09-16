# Network event NDJSON schema version 3

## Status

Schema version 3 is introduced for expanded protocol visibility without changing
the frozen attempt-only schema version 1 or TCP lifecycle schema version 2.

The first version 3 event is `udp_send`.

## UDP semantics

UDP does not have a TCP-style connection lifecycle. A `udp_send` event means
only that the kernel observed an outbound UDP send with an explicit destination
address supplied through the send path used by `sendto` or `sendmsg`.

It does **not** prove:

- delivery;
- reachability;
- receipt by a remote process;
- application-layer success;
- any persistent UDP connection state.

Connected UDP destination observation through `connect()` remains compatible
with the existing attempt-only collection path. Version 3 adds visibility for
unconnected per-datagram destinations.

## Collection mode

Enable expanded UDP visibility with:

```text
--udp
```

`--udp` and `--tcp-lifecycle` are intentionally mutually exclusive. This keeps
each NDJSON stream on exactly one public schema version instead of mixing TCP
schema version 2 and UDP schema version 3 records.

## Common UDP record

A `udp_send` record contains:

- `schema_version`: integer `3`;
- `event_type`: `udp_send`;
- `observed_at`: userspace UTC observation timestamp in RFC 3339 format;
- `kernel_timestamp_ns`: monotonic kernel timestamp for the send observation;
- `protocol`: `udp`;
- `address_family`: `AF_INET` or `AF_INET6`;
- `process`: process metadata known at observation time;
- `remote`: explicit destination endpoint.

There is deliberately no `result`, `connection_id`, connect latency, or
connection duration field for UDP sends.

## Process object

The `process` object always contains:

- `pid`: thread-group ID of the sending process;
- `uid`: real user ID observed by the BPF program.

It may also contain the same additive process-attribution fields used by TCP
lifecycle schema version 2:

- `gid`: real group ID when userspace process context is available;
- `comm`: kernel task command name;
- `executable`: resolved executable path;
- `user`: resolved user name, or the numeric UID when name lookup fails;
- `start_time_ticks`: Linux process start identity from `/proc/<pid>/stat`;
- `parent`: parent PID and parent start identity;
- `cgroup`: kernel cgroup ID and cgroup path when available;
- `namespaces`: cgroup, IPC, mount, network, PID, user, and UTS namespace inode
  identifiers;
- `container`: best-effort container runtime and container ID inferred from the
  cgroup path.

When `-a` is enabled, `arguments` may also be present.

Process execution and exit are observed independently and cached in a bounded,
PID-generation-aware userspace cache. This prevents a later process that reuses
the same PID from being silently substituted for an earlier sender.

Container metadata is best effort. The tracer does not contact a container
runtime, Docker daemon, or Kubernetes API.

## ASN object

When `-a` is enabled and the remote IP matches the loaded offline ASN data, an
optional top-level `asn` object may be emitted with:

- `number`: autonomous-system number;
- `name`: autonomous-system name when available.

## DNS object

When `--dns` is enabled and reverse lookup of the remote IP succeeds, an
optional top-level `dns` object may be emitted with:

- `name`: normalized PTR name returned by the resolver;
- `source`: `reverse_dns`;
- `confidence`: `low`.

This metadata does not prove that the sending process requested, queried, or
used the returned hostname. It is only a reverse-DNS correlation for the
observed IP at enrichment time. See `DNS_ENRICHMENT.md` for cache, timeout,
privacy, and performance semantics.

## Remote endpoint

`remote` contains:

- `ip`: explicit IPv4 or IPv6 destination supplied to the UDP send;
- `port`: explicit destination UDP port.

Both are required for a valid `udp_send` record. Sends without an explicit
`msg_name` are not represented by this event because the destination is not
present in the send request itself. For connected UDP, destination visibility
continues to come from the existing `connect()` observation path.

## Filtering

PID, UID, family, and destination-port filters are applied in the UDP eBPF
program before accepted events are submitted to the UDP ring buffer.

Repeated values within one filter category use OR semantics. Different
categories use AND semantics, matching the existing kernel-filter contract.

UDP mode supports `ipv4` and `ipv6` family matches. `other` does not match a
UDP version 3 event because the current UDP event contract is limited to
explicit IPv4 and IPv6 destinations.

## Example

```json
{"schema_version":3,"event_type":"udp_send","observed_at":"2026-09-15T20:00:00Z","kernel_timestamp_ns":123456,"protocol":"udp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"sender","executable":"/usr/bin/python3","user":"alice","cgroup":{"id":99,"path":"/user.slice/user-1000.slice/session-2.scope"}},"remote":{"ip":"192.0.2.25","port":5353}}
```

## Compatibility

Schema version 1 remains frozen for attempt-only output.

Schema version 2 remains the TCP lifecycle contract.

Version 3 must not reinterpret an existing version 1 or version 2 field. New
optional metadata may be added while preserving existing meanings.
