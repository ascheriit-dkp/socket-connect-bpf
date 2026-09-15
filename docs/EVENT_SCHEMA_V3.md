# Network event NDJSON schema version 3

## Status

Schema version 3 is introduced for expanded protocol visibility without changing
the frozen attempt-only schema version 1 or TCP lifecycle schema version 2.

The first version 3 event is `udp_send`.

## UDP semantics

UDP does not have a TCP-style connection lifecycle. An `udp_send` event means
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

## Common UDP record

An `udp_send` record contains:

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

The initial UDP event pipeline always provides:

- `pid`: thread-group ID of the sending process;
- `uid`: real user ID observed by the BPF program.

It may also provide:

- `comm`: kernel task command name;
- `cgroup_id`: kernel cgroup ID when non-zero.

Phase 5 runtime integration may add the same optional process-enrichment fields
used by TCP lifecycle events. Such additions are compatible because consumers
must ignore unknown optional fields.

## Remote endpoint

`remote` contains:

- `ip`: explicit IPv4 or IPv6 destination supplied to the UDP send;
- `port`: explicit destination UDP port.

Both are required for a valid `udp_send` record. Sends without an explicit
`msg_name` are not represented by this event because the destination is not
present in the send request itself.

## Example

```json
{"schema_version":3,"event_type":"udp_send","observed_at":"2026-09-15T20:00:00Z","kernel_timestamp_ns":123456,"protocol":"udp","address_family":"AF_INET","process":{"pid":1234,"uid":1000,"comm":"sender","cgroup_id":99},"remote":{"ip":"192.0.2.25","port":5353}}
```

## Compatibility

Schema version 1 remains frozen for attempt-only output.

Schema version 2 remains the TCP lifecycle contract.

Version 3 must not reinterpret an existing version 1 or version 2 field. New
optional metadata may be added while preserving existing meanings.
