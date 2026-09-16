# DNS correlation

## Status

DNS correlation is optional and does not generate DNS traffic.

Load one or more pre-collected DNS observation files with:

```bash
sudo socket-connect-bpf \
  --tcp-lifecycle \
  --output ndjson \
  --dns-observations /path/to/dns.jsonl
```

The same observation source can be used with `--udp`.

The compatibility/schema v1 stream remains unchanged and does not emit DNS metadata.

## Observation format

Each non-empty, non-comment line is one JSON object:

```json
{"ip":"203.0.113.10","name":"api.example","observed_at":"2026-09-16T08:00:00Z","ttl_seconds":60,"pid":4242,"source":"resolver-log"}
```

Required fields:

- `ip`: IPv4 or IPv6 address returned by DNS.
- `name`: DNS name. A trailing dot is normalized away.
- `observed_at`: wall-clock observation time in RFC 3339 format.
- `ttl_seconds`: positive TTL used to bound the correlation window.

Optional fields:

- `pid`: process ID associated with the DNS observation.
- `source`: short identifier for the observation source. It defaults to `dns_observation_file`.

Unknown fields and invalid records are rejected before tracing starts.

Files may contain blank lines and lines beginning with `#`.

`--dns-observations` may be repeated. The in-memory observation cache is bounded to 65,536 records.

## Correlation semantics

For a network event with a remote IP, the tracer considers only observations where:

```text
observation.observed_at <= event.observed_at <= observation.expires_at
```

where:

```text
observation.expires_at = observation.observed_at + ttl_seconds
```

Confidence values:

- `high`: the observation IP matches the remote IP and the observation PID matches the network-event PID.
- `medium`: the observation IP matches the remote IP but the observation is process-agnostic.

A PID-specific observation for another PID is ignored.

Expired observations, observations from the future, and observations for another IP are ignored.

If multiple valid observations exist, higher confidence wins. Within the same confidence level, the newest observation wins.

## Output

TCP lifecycle schema v2 and UDP schema v3 may include:

```json
"dns": {
  "name": "api.example",
  "source": "resolver-log",
  "confidence": "high",
  "observed_at": "2026-09-16T08:00:00Z",
  "expires_at": "2026-09-16T08:01:00Z"
}
```

Absence of `dns` means no valid observation matched. It does not mean that DNS was not used.

## Security and correctness boundary

This feature is correlation, not proof of causation.

A `high` result means the observation source associated the same PID with that DNS answer and the answer was still valid when the network event was observed. It does not prove that a particular socket was created because of that DNS response.

A `medium` result is weaker: another process on the host may have produced the observation.

The tracer does not issue PTR queries, call the system resolver, or otherwise create network requests to enrich an event. This avoids self-generated DNS traffic and prevents a reverse lookup from being presented as evidence of what the observed process resolved.
