# Process argument redaction

## Status

Argument redaction is optional and applies to process arguments captured for extended output.

Enable argument capture with `-a` and add one or more redaction rules with repeated `--redact-arg` flags:

```bash
sudo socket-connect-bpf \
  -a \
  --redact-arg '(?i)token=[^ ]+' \
  --redact-arg '(?i)password=[^ ]+'
```

Matching text is replaced with:

```text
[REDACTED]
```

The same behavior applies to:

- compatibility / schema v1 output;
- TCP lifecycle / schema v2 output;
- UDP visibility / schema v3 output.

## Matching semantics

`--redact-arg` accepts Go regular expressions.

The flag may be repeated. Rules are applied in the order supplied.

Limits:

- maximum 64 patterns;
- maximum 1024 bytes per pattern;
- empty patterns are rejected;
- patterns that match empty text are rejected;
- invalid regular expressions are rejected before tracing starts.

Existing `[REDACTED]` markers are preserved so repeated enrichment paths do not expand or mutate already-redacted values.

## Cache behavior

In lifecycle and UDP modes, process arguments are redacted when they are captured from `/proc/<pid>/cmdline`, before the value is stored in the bounded process cache.

The TCP fallback path also redacts arguments before connection-level enrichment is cached.

The compatibility mode has no persistent process cache; its `/proc` argument value is redacted before it is emitted.

This prevents configured matches from being retained in the tool's userspace process/enrichment caches in clear text.

## Examples

Redact bearer-style tokens:

```bash
sudo socket-connect-bpf \
  --tcp-lifecycle \
  -a \
  --output ndjson \
  --redact-arg '(?i)bearer [A-Za-z0-9._-]+'
```

Redact common CLI secret assignments:

```bash
sudo socket-connect-bpf \
  --udp \
  -a \
  --output ndjson \
  --redact-arg '(?i)(token|password|secret)=[^ ]+'
```

## Security boundary

Redaction is pattern-based, not automatic secret detection.

A value that does not match a configured rule is not redacted. Applications can also expose sensitive information through environment variables, files, network payloads, process names, or other sources that this feature does not inspect.

Use narrowly defined rules that match the argument forms used by the processes being observed.
