# Export and integration examples

## Status

socket-connect-bpf writes event data to standard output and diagnostics to standard error.

For automation, use NDJSON output. Each line is one complete JSON object and can be processed incrementally without waiting for the tracer to exit.

Schema selection follows the collection mode:

- compatibility mode: schema version 1;
- `--tcp-lifecycle`: schema version 2;
- `--udp`: schema version 3.

See the versioned schema documents for field semantics. Integration code should ignore unknown optional fields so additive metadata does not break consumers.

## Export to a file

Keep event data and tracer diagnostics separate:

```bash
sudo ./socket-connect-bpf \
  --tcp-lifecycle \
  --output ndjson \
  >events.ndjson \
  2>tracer.log
```

The same pattern works with compatibility and UDP modes.

## Filter with jq

Show failed TCP lifecycle events:

```bash
jq -c \
  'select(.schema_version == 2 and .event_type == "tcp_connect_failed")' \
  events.ndjson
```

Show UDP sends:

```bash
jq -c \
  'select(.schema_version == 3 and .event_type == "udp_send")' \
  events.ndjson
```

Show events that contain DNS correlation metadata:

```bash
jq -c \
  'select(.dns != null) | {process: .process.comm, remote: .remote, dns: .dns}' \
  events.ndjson
```

DNS metadata is correlation, not proof that the observed network event was caused by a DNS response. Preserve `dns.source` and `dns.confidence` when exporting it.

## Convert NDJSON to CSV

`examples/ndjson_to_csv.py` converts schema versions 1, 2, and 3 into a compact common CSV view using only the Python standard library:

```bash
sudo ./socket-connect-bpf \
  --tcp-lifecycle \
  --output ndjson \
  2>tracer.log | \
  python3 examples/ndjson_to_csv.py \
  >events.csv
```

The converter keeps the versioned event type and exposes common process, destination, result, DNS, and ASN fields. Fields that do not exist for a schema are left empty instead of being fabricated.

## CI failure gate

`examples/check_tcp_failures.py` is a minimal line-oriented consumer for schema version 2. It exits with status 1 if one or more `tcp_connect_failed` events are present.

```bash
sudo timeout \
  --preserve-status \
  --signal=INT \
  10s \
  ./socket-connect-bpf \
  --tcp-lifecycle \
  --output ndjson \
  >events.ndjson \
  2>tracer.log

python3 examples/check_tcp_failures.py <events.ndjson
```

This example is intentionally narrow. A failed TCP connection may be expected application behaviour, so production CI should add process, destination, or port conditions that match the policy being tested.

## Stream into another process

Because NDJSON is line-oriented, a consumer can process events as they arrive:

```bash
sudo ./socket-connect-bpf \
  --udp \
  --output ndjson \
  2>tracer.log | \
  your-consumer
```

The downstream process should:

- read one JSON object per line;
- branch on `schema_version` and `event_type`;
- tolerate unknown optional fields;
- treat missing optional fields as unknown, not as zero or false;
- preserve `connection_id` only as an opaque per-run TCP correlation key;
- keep stderr separate from the event stream.

## DNS observation input

DNS correlation consumes observations supplied by the user. The tracer does not perform PTR or other network lookups itself.

A sample file is included at `examples/dns-observations.example.jsonl`.

Load it with:

```bash
sudo ./socket-connect-bpf \
  --tcp-lifecycle \
  --output ndjson \
  --dns-observations examples/dns-observations.example.jsonl
```

The sample uses documentation-only IP addresses and is not expected to match normal traffic. Replace it with observations from the resolver or logging source used in the environment.

The exact DNS observation contract, TTL handling, PID matching, and confidence levels are documented in `docs/DNS_CORRELATION.md`.

## Sensitive process arguments

If `-a` is enabled, process arguments may contain credentials or other sensitive values. Configure `--redact-arg` rules before exporting or forwarding events when such values may be present.

Example:

```bash
sudo ./socket-connect-bpf \
  --tcp-lifecycle \
  -a \
  --redact-arg '(?i)(token|password|secret)=[^ ]+' \
  --output ndjson \
  >events.ndjson \
  2>tracer.log
```

Argument redaction is pattern-based. Values that do not match a configured rule are not redacted. See `docs/ARGUMENT_REDACTION.md`.

## Example validation

Repository examples are checked with:

```bash
bash scripts/test-export-examples.sh
```

The test verifies Python syntax, schema 1/2/3 CSV conversion, the TCP failure gate exit status, and the DNS observation fixture shape.
