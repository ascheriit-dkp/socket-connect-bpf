# Kernel-side filter contract

## Status

This document defines the kernel-side filtering contract for socket-connect-bpf
v2 collection modes.

The implementation supports filtering by:

- Process ID.
- User ID.
- Address-family category.
- Destination port.

The same command-line contract applies to:

- compatibility attempt-only collection;
- TCP lifecycle collection;
- UDP visibility collection.

Filtering is observational only. It does not block or alter network activity.

## Goals

Kernel-side filtering should:

- Avoid transferring unwanted events to userspace.
- Reduce ring-buffer pressure.
- Reduce userspace process and ASN enrichment work.
- Preserve existing behaviour when no filter is configured.
- Fail clearly rather than silently ignoring invalid filter values.
- Remain simple enough to audit and test.

## Command-line interface

The command-line options are:

    --pid PID
    --uid UID
    --family FAMILY
    --port PORT

Each option may be specified more than once.

Examples:

    sudo ./socket-connect-bpf --pid 1234

    sudo ./socket-connect-bpf \
      --tcp-lifecycle \
      --uid 1000 \
      --family ipv4 \
      --port 443

    sudo ./socket-connect-bpf \
      --udp \
      --family ipv4 \
      --port 53 \
      --output ndjson

## Combination semantics

Values within the same filter category use OR semantics.

For example:

    --pid 1234 --pid 5678

matches events whose process ID is either `1234` or `5678`.

Different filter categories use AND semantics.

For example:

    --uid 1000 --port 443

matches only events whose UID is `1000` and whose destination port is `443`.

Formally, an event is accepted when:

    pid_matches
    AND uid_matches
    AND family_matches
    AND port_matches

A filter category with no configured values always matches.

Therefore, running without any filter options preserves the unfiltered
behaviour of the selected collection mode.

## Process-ID filter

`--pid` accepts an unsigned decimal process ID greater than zero.

The value matches the process identifier exposed as `process.pid` in NDJSON and
as the process ID in table output.

Internally, this is the thread-group ID obtained from the upper 32 bits of
`bpf_get_current_pid_tgid()`. Threads belonging to the same process therefore
match the same `--pid` value.

Examples:

    --pid 1
    --pid 1234

The value `0` is rejected.

For TCP lifecycle mode the PID decision is made when the outbound connection is
initiated. Later lifecycle events inherit that decision.

For UDP visibility mode the PID decision is made for each observed `udp_send`.

## User-ID filter

`--uid` accepts an unsigned decimal UID.

The value matches the UID captured for the event by the BPF program.

UID `0` is valid.

Examples:

    --uid 0
    --uid 1000

Names such as `root` are not accepted. This keeps parsing deterministic and
avoids environment-dependent name resolution.

For TCP lifecycle mode the UID decision is made at the initiating attempt and is
preserved for later lifecycle events.

For UDP visibility mode the UID decision is made for each observed `udp_send`.

## Address-family filter

`--family` accepts one of:

- `ipv4`
- `ipv6`
- `other`

The values are case-sensitive.

Their meanings are:

| Value | Matching events |
| --- | --- |
| `ipv4` | `AF_INET` events |
| `ipv6` | `AF_INET6` events |
| `other` | Supported non-IP families in compatibility attempt-only mode |

Examples:

    --family ipv4

    --family ipv4 --family ipv6

Compatibility attempt-only mode retains its existing exclusions for
`AF_UNSPEC` and `AF_UNIX`. Selecting `other` does not cause those families to be
emitted.

TCP lifecycle mode and UDP visibility mode currently observe only IPv4 and IPv6.
`--family other` therefore matches no events in those modes.

Exact numeric filtering for individual non-IP address families is outside the
scope of this contract.

## Destination-port filter

`--port` accepts an unsigned decimal destination port from `1` through `65535`.

Examples:

    --port 53
    --port 80 --port 443

Port filters apply to IPv4 and IPv6 events in every collection mode.

In compatibility and TCP lifecycle modes the port is the outbound connect
destination port.

In UDP visibility mode the port is the explicit per-datagram destination port
observed from the `sendto` or `sendmsg` path.

Supported non-IP compatibility events do not contain a destination port. When
any port filter is active, those events do not match.

Port `0` is rejected because IP events with destination port zero are not part
of the supported output contract.

## Duplicate values

Duplicate values are accepted and treated as one value.

For example:

    --port 443 --port 443

has the same meaning as:

    --port 443

## Invalid input

The program must fail before attaching the active collection probes when:

- A PID is malformed, zero, or outside the `uint32` range.
- A UID is malformed or outside the `uint32` range.
- A family value is unsupported.
- A port is malformed, zero, or greater than `65535`.
- A filter category exceeds its supported entry limit.
- A configured filter cannot be written to its BPF map.

Invalid values must never be silently ignored or truncated.

## Capacity limits

The implementation supports at most:

- 1024 distinct process IDs.
- 1024 distinct user IDs.
- 1024 distinct destination ports.
- All three address-family categories at the command-line layer.

These limits bound BPF map memory and startup work.

Attempting to exceed a limit causes startup to fail with a descriptive error.

## Kernel implementation

The compatibility/TCP program and UDP visibility program use separate BPF
objects and separate filter maps, but they share the same userspace filter
configuration contract.

Each active collector uses:

- One configuration map containing enabled-filter flags and the selected
  address-family mask.
- One hash-set map for process IDs.
- One hash-set map for user IDs.
- One hash-set map for destination ports.

Userspace populates every configured membership map before enabling the filter
configuration and before attaching the collection probes.

This prevents a startup interval in which unfiltered matching events could be
emitted.

## Evaluation order

The BPF programs reject events as early as the required data becomes available:

1. Read the current process ID and UID.
2. Apply PID and UID filters.
3. Determine the destination address family.
4. Apply the address-family filter.
5. For IPv4 or IPv6, read and validate the destination port.
6. Apply the destination-port filter.
7. Build and submit the event record.

For TCP lifecycle mode this evaluation is performed at the initiating attempt;
accepted connections create lifecycle correlation state and later events
inherit the original filter decision.

For UDP visibility mode the evaluation is performed independently for each
explicit-destination UDP send.

## Event-loss accounting

Events intentionally rejected by filters are not lost events.

They must not increment a ring-buffer dropped-event counter.

The compatibility/TCP ring buffer and UDP ring buffer maintain their own loss
accounting. A dropped-event counter represents events that matched all active
filters but could not be submitted because ring-buffer space was unavailable.

## Output compatibility

Filtering does not reinterpret event records or public NDJSON schemas.

Events that pass every configured filter retain the selected mode's normal:

- Internal ABI.
- Table format.
- NDJSON schema version.
- Enrichment behaviour.
- Event-loss reporting.

That means filtering preserves:

- schema version `1` for compatibility attempt-only NDJSON;
- schema version `2` for TCP lifecycle NDJSON;
- schema version `3` for UDP visibility NDJSON.

## Non-goals

This filtering contract does not add filtering by:

- Destination IP address or CIDR.
- Process name or executable path.
- Command-line arguments.
- GID.
- Cgroup.
- Container.
- Network namespace.
- Protocol.
- Connection result.
- Dynamic runtime filter updates.

Those filters may be added later without changing the combination semantics
defined here.

## Testing requirements

Unit tests must cover:

- Repeated PID, UID, family, and port options.
- Duplicate-value handling.
- OR semantics within a category.
- AND semantics across categories.
- Every invalid-value boundary.
- Capacity-limit enforcement.
- Empty filters preserving unfiltered behaviour.

Live compatibility/TCP tests must prove that:

- A matching PID is emitted.
- A non-matching PID is excluded.
- A matching IPv4 destination port is emitted.
- A non-matching destination port is excluded.
- IPv4 and IPv6 family filters work independently.
- Combined filters use AND semantics.
- Filtered events do not appear in table or NDJSON output.
- Shutdown event-loss reporting still works.

Live UDP tests must additionally prove that:

- PID filtering applies to the process issuing the UDP send.
- UID filtering rejects a sender with a different UID.
- IPv4 family filtering rejects an IPv6 UDP send.
- Destination-port filtering rejects a datagram sent to another port.
- Combined family and port filtering uses AND semantics.
- Accepted events remain schema version `3` `udp_send` records.
- Filtered observations do not increment the UDP dropped-event counter.
