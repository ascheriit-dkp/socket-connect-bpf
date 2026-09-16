# Reverse DNS enrichment

## Status

Reverse DNS enrichment is optional.

Enable it with `--dns` together with TCP lifecycle or UDP visibility:

```bash
sudo socket-connect-bpf --tcp-lifecycle --dns
sudo socket-connect-bpf --udp --dns
```

The compatibility NDJSON schema v1 remains unchanged and does not expose DNS enrichment.

## What the feature proves

The implementation performs a reverse lookup for the observed remote IP address.

A successful correlation is always labeled:

```text
source = reverse_dns
confidence = low
```

A PTR result does **not** prove that the observed application queried, requested, or used that hostname. It only proves that the resolver returned that reverse-DNS name for the IP at enrichment time.

The tool must therefore not describe this field as the destination domain requested by the process.

## Output

TCP lifecycle schema v2 and UDP schema v3 may add the optional top-level object:

```json
"dns": {
  "name": "example.net",
  "source": "reverse_dns",
  "confidence": "low"
}
```

The field is omitted when:

- `--dns` is not enabled;
- the remote address is unavailable;
- the resolver returns no usable PTR name;
- the lookup fails or times out.

Names are normalized to lower case and a final DNS root dot is removed.

Human-readable TCP and UDP table output appends the same metadata to the remote endpoint when a correlation exists:

```text
192.0.2.10:443 (example.net [reverse_dns/low])
```

Without `--dns`, table output remains unchanged.

## Cache and timeout

Reverse lookups are synchronous but bounded.

Defaults:

```text
lookup timeout       250 ms
cache entries        4096
positive cache TTL   10 min
negative cache TTL   1 min
```

The cache is bounded and evicts least-recently-used entries. Both successful and failed lookups are cached so repeated events for the same address do not continuously hit the resolver.

TCP lifecycle events for the same remote IP therefore normally pay the lookup cost only once during the cache lifetime.

## Performance

DNS enrichment is disabled by default because resolver latency is external to the eBPF event pipeline and can delay userspace event processing.

The timeout limits one lookup, but enabling `--dns` for workloads that contact many previously unseen addresses can still reduce event-processing throughput and increase the chance of ring-buffer loss under load.

Use the existing loss counters when evaluating the feature on busy systems.

## Privacy and network behavior

Reverse DNS may cause resolver traffic according to the host's resolver configuration. Depending on `/etc/resolv.conf`, NSS configuration, VPNs, containers, or local caching services, lookups may leave the machine.

Do not enable `--dns` when that resolver traffic is undesirable.

The cache exists only in process memory and is discarded when the tracer exits.
