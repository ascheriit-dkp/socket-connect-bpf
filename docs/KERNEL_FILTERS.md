# Kernel-side filter contract

## Status

This document defines the initial kernel-side filtering contract for
socket-connect-bpf v2.

The first implementation supports filtering connection-attempt events by:

- Process ID.
- User ID.
- Address-family category.
- Destination port.

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

The initial command-line options are:

    --pid PID
    --uid UID
    --family FAMILY
    --port PORT

Each option may be specified more than once.

Examples:

    sudo ./socket-connect-bpf --pid 1234

    sudo ./socket-connect-bpf \
      --uid 1000 \
      --family ipv4

    sudo ./socket-connect-bpf \
      --pid 1234 \
      --pid 5678 \
      --port 80 \
      --port 443

    sudo ./socket-connect-bpf \
      --family ipv4 \
      --family ipv6 \
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

Formally, an event is emitted when:

    pid_matches
    AND uid_matches
    AND family_matches
    AND port_matches

A filter category with no configured values always matches.

Therefore, running without any filter options preserves the existing
unfiltered behaviour.

## Process-ID filter

`--pid` accepts an unsigned decimal process ID greater than zero.

The value matches the process identifier currently exposed as `pid` by
socket-connect-bpf.

Internally, this is the thread-group ID obtained from the upper 32 bits of
`bpf_get_current_pid_tgid()`. Threads belonging to the same process therefore
match the same `--pid` value.

Examples:

    --pid 1
    --pid 1234

The value `0` is rejected.

## User-ID filter

`--uid` accepts an unsigned decimal UID.

The value matches the UID captured for the event by the BPF program.

UID `0` is valid.

Examples:

    --uid 0
    --uid 1000

Names such as `root` are not accepted in this initial implementation. This
keeps parsing deterministic and avoids environment-dependent name resolution.

## Address-family filter

`--family` accepts one of:

- `ipv4`
- `ipv6`
- `other`

The values are case-sensitive.

Their meanings are:

| Value   | Matching events                                      |
|---------|------------------------------------------------------|
| `ipv4`  | `AF_INET` events                                     |
| `ipv6`  | `AF_INET6` events                                    |
| `other` | Emitted non-IP families other than `AF_UNSPEC` and `AF_UNIX` |

Examples:

    --family ipv4

    --family ipv4 --family ipv6

The existing exclusions for `AF_UNSPEC` and `AF_UNIX` remain unchanged.
Selecting `other` does not cause those families to be emitted.

Exact numeric filtering for individual non-IP address families is outside the
scope of the initial implementation.

## Destination-port filter

`--port` accepts an unsigned decimal destination port from `1` through
`65535`.

Examples:

    --port 53
    --port 80 --port 443

Port filters apply to IPv4 and IPv6 events.

Supported non-IP events do not contain a destination port. When any port
filter is active, those events do not match.

Port `0` is rejected because the tracer already excludes IP events whose
destination port is zero.

## Duplicate values

Duplicate values are accepted and treated as one value.

For example:

    --port 443 --port 443

has the same meaning as:

    --port 443

## Invalid input

The program must fail before attaching the BPF probe when:

- A PID is malformed, zero, or outside the `uint32` range.
- A UID is malformed or outside the `uint32` range.
- A family value is unsupported.
- A port is malformed, zero, or greater than `65535`.
- A filter category exceeds its supported entry limit.
- A configured filter cannot be written to its BPF map.

Invalid values must never be silently ignored or truncated.

## Capacity limits

The initial implementation supports at most:

- 1024 distinct process IDs.
- 1024 distinct user IDs.
- 1024 distinct destination ports.
- All three address-family categories.

These limits bound BPF map memory and startup work.

Attempting to exceed a limit causes startup to fail with a descriptive error.

## Kernel implementation

The initial implementation uses:

- One configuration map containing enabled-filter flags and the selected
  address-family mask.
- One hash-set map for process IDs.
- One hash-set map for user IDs.
- One hash-set map for destination ports.

Userspace populates every configured filter before attaching the
`security_socket_connect` probe.

This prevents a startup interval in which unfiltered events could be emitted.

## Evaluation order

The BPF program should reject events as early as the required data becomes
available:

1. Read the current process ID and UID.
2. Apply PID and UID filters.
3. Read the destination address family.
4. Apply the address-family filter.
5. For IPv4 or IPv6, read and validate the destination port.
6. Apply the destination-port filter.
7. Build and submit the event record.

This order avoids unnecessary socket reads, task-name reads, timestamps, and
ring-buffer writes.

## Event-loss accounting

Events intentionally rejected by filters are not lost events.

They must not increment the ring-buffer dropped-event counter.

The dropped-event counter continues to represent events that matched all
filters but could not be submitted because the ring buffer had insufficient
space.

## Output compatibility

Filtering does not alter the event record or the public NDJSON schema.

Events that pass every configured filter use the same:

- Internal ABI version.
- Table format.
- NDJSON schema version.
- Enrichment behaviour.
- Event-loss reporting.

## Initial non-goals

This milestone does not add filtering by:

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

The implementation must include unit tests for:

- Repeated PID, UID, family, and port options.
- Duplicate-value handling.
- OR semantics within a category.
- AND semantics across categories.
- Every invalid-value boundary.
- Capacity-limit enforcement.
- Empty filters preserving unfiltered behaviour.

Live integration tests must prove that:

- A matching PID is emitted.
- A non-matching PID is excluded.
- A matching IPv4 destination port is emitted.
- A non-matching destination port is excluded.
- IPv4 and IPv6 family filters work independently.
- Combined filters use AND semantics.
- Filtered events do not appear in table or NDJSON output.
- Shutdown event-loss reporting still works.
