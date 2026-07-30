# NDJSON Event Schema v1

## Status

This document defines version 1 of the public NDJSON event contract emitted by
socket-connect-bpf.

The schema describes observable output compatibility. Internal kernel event
structures, transport mechanisms, and enrichment implementations may change
without changing this contract.

## Selecting NDJSON output

Run the tracer with:

    sudo ./socket-connect-bpf --output ndjson

Include process arguments and ASN enrichment with:

    sudo ./socket-connect-bpf --output ndjson -a

ASN data must be available when `-a` is enabled.

## Framing

The output is newline-delimited JSON.

Each line contains one complete JSON object. There is no header, opening array,
closing array, or separator other than the newline terminating each event.

Consumers should process each non-empty line independently.

## Event semantics

Schema version 1 currently defines the event type:

    connect_attempt

A `connect_attempt` event means that the tracer observed a process entering the
Linux `security_socket_connect` hook.

It does not prove that the connection succeeded.

The event may represent a connection that:

- succeeded immediately;
- completed asynchronously;
- failed immediately;
- failed later;
- was rejected by security policy.

Connection outcome and lifecycle events are outside the current schema.

## Basic example

Without `-a`, an IPv4 event resembles:

    {
      "schema_version": 1,
      "event_type": "connect_attempt",
      "observed_at": "2026-07-30T12:00:00.123456789Z",
      "address_family": "AF_INET",
      "process": {
        "pid": 4242,
        "comm": "curl",
        "executable": "/usr/bin/curl",
        "user": "alice"
      },
      "destination": {
        "ip": "203.0.113.10",
        "port": 443
      }
    }

The real NDJSON stream emits this object on one line.

## Extended example

With `-a`, an enriched event may include process arguments and ASN data:

    {
      "schema_version": 1,
      "event_type": "connect_attempt",
      "observed_at": "2026-07-30T12:00:00.123456789Z",
      "address_family": "AF_INET",
      "process": {
        "pid": 4242,
        "comm": "curl",
        "executable": "/usr/bin/curl",
        "arguments": "curl https://example.com/",
        "user": "alice"
      },
      "destination": {
        "ip": "203.0.113.10",
        "port": 443
      },
      "asn": {
        "number": 64500,
        "name": "Example Network"
      }
    }

## Top-level object

### `schema_version`

Required JSON number.

The value is:

    1

Consumers must inspect this field before interpreting the rest of the event.

### `event_type`

Required JSON string.

The currently defined value is:

    connect_attempt

Consumers must not interpret unknown event types as connection attempts.

Additional event types may be introduced later and documented separately.

### `observed_at`

Required JSON string.

The value uses RFC 3339 format with nanosecond precision and is normalized to
UTC.

In the current implementation this is the userspace observation time, recorded
after the event is read from the perf-event stream.

It is not the precise kernel hook timestamp. Queueing, scheduling, decoding,
and enrichment delay can separate it from the actual connection attempt.

A future kernel timestamp must use a separate documented field or a new schema
version if it changes the meaning of `observed_at`.

### `address_family`

Required JSON string.

Common values include:

    AF_INET
    AF_INET6

Other Linux address-family names may appear.

Consumers must not assume that every event is IPv4 or IPv6.

### `process`

Required JSON object containing process information.

### `destination`

Required JSON object containing the remote destination information available
for the observed address family.

The object can be empty for unsupported or non-IP address families.

### `asn`

Optional JSON object.

It is emitted only when extended output is enabled and ASN information was
resolved.

## Process object

### `pid`

Required JSON number.

The value is the process identifier supplied by the kernel event.

It is an unsigned 32-bit value in the current implementation.

### `comm`

Optional JSON string.

The value is the kernel task command name captured with the event.

It can differ from the executable filename and does not contain the complete
command line.

### `executable`

Optional JSON string.

The value is resolved in userspace from `/proc` after event receipt.

The field can be absent when the process exits before enrichment completes,
when access is denied, or when the executable cannot be resolved.

Consumers must not use this field as a guaranteed process identity.

### `arguments`

Optional JSON string.

The field is emitted only when extended output is enabled and arguments are
available.

The value is resolved from `/proc` after event receipt and can be absent for
short-lived processes, inaccessible processes, kernel threads, or other
enrichment failures.

JSON escaping preserves embedded newlines, tabs, control characters, and
backslashes without breaking NDJSON framing.

### `user`

Optional JSON string.

The tracer attempts to resolve the numeric user identifier through the local
user database.

When name resolution fails, the current implementation uses the decimal user
identifier as the value.

## Destination object

### `ip`

Optional JSON string.

For IPv4 and IPv6 events, this contains the textual destination address.

The field can be absent for non-IP address families or unavailable destination
data.

Consumers must support both IPv4 and IPv6 textual forms.

### `port`

Optional JSON number.

For IP events, this contains the destination port as an unsigned 16-bit value.

Because unavailable and zero-valued optional fields are omitted by the current
encoder, consumers must not assume the field is always present.

## ASN object

### `number`

Required JSON number when the `asn` object is present.

The value is the resolved autonomous system number as an unsigned 32-bit
value.

### `name`

Optional JSON string.

The value is the description supplied by the configured ASN dataset.

Consumers must not treat the description as a stable organization identifier.

## Missing data

Optional data is omitted rather than represented by an empty placeholder
object or a JSON `null` value.

Consumers must tolerate missing optional fields.

Process enrichment is performed after the kernel event is received. A process
can exit, change state, or make its `/proc` data unavailable before enrichment
finishes.

ASN information can be absent for private, reserved, unknown, or uncovered
addresses.

## Ordering

Events are emitted as they are processed by concurrent address-family readers.

The stream does not currently guarantee strict ordering by kernel occurrence
time, process, address family, or userspace observation time.

JSON object field ordering is not part of the contract.

## Compatibility rules

Within schema version 1, the producer may:

- add optional fields;
- add optional nested objects;
- add separately documented event types;
- emit previously optional information more consistently.

Within schema version 1, the producer must not:

- remove a required field;
- change a field's JSON type;
- change the meaning of an existing field;
- reinterpret `connect_attempt` as successful connection establishment;
- rename an existing field;
- make an optional field required.

A breaking change requires a new `schema_version`.

Consumers should:

- reject or separately handle unsupported schema versions;
- branch on `event_type`;
- ignore unknown fields;
- tolerate missing optional fields;
- avoid relying on field order;
- process each NDJSON line independently.

## Security considerations

Process arguments, paths, usernames, ASN descriptions, and other strings are
untrusted data.

Consumers must apply context-appropriate escaping before placing values into
terminals, HTML, SQL, shell commands, logs, or other interpreters.

The NDJSON encoder protects JSON framing but does not make values safe for
unrelated output contexts.
