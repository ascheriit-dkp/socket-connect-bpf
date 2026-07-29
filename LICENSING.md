# Licensing

This repository contains project code, inherited code, generated files,
vendored headers, dependencies, and external data under different licensing
terms.

A single licence must not be assumed to apply to every file in the repository.

## Go and userspace project code

The upstream project states that its Go code is licensed under the Apache
License, Version 2.0.

Existing copyright and attribution notices from the upstream project must be
preserved.

Unless a file states otherwise, Go code, tests, workflows, and documentation
newly authored by Ascheriit-Dkp for v2 are licensed under the Apache License,
Version 2.0.

The SPDX identifier for this licence is `Apache-2.0`.

## Inherited BPF source

The inherited BPF source file `securitySocketConnectSrc.c` contains the
kernel-facing licence declaration:

`char LICENSE[] SEC("license") = "Dual MIT/GPL";`

The upstream README separately describes the BPF code as GPL-licensed.

The `Dual MIT/GPL` ELF licence string is used by the Linux kernel when loading
the BPF program. It indicates GPL compatibility and a dual MIT/GPL licensing
choice, but it is not a substitute for a clear source-level licence declaration
and does not identify an exact GPL variant by itself.

For the inherited BPF source:

- Preserve its original provenance and kernel-facing licence declaration.
- Do not describe it as Apache-2.0 code.
- Do not claim a more specific GPL variant than the inherited source supports.
- Avoid copying substantial third-party BPF implementations into it without a
  separate licence review.

Replacement BPF source newly authored for v2 must include an explicit SPDX
licence identifier before it is merged.

## Vendored libbpf headers

Files copied from libbpf under `headers/` retain their existing SPDX
declarations.

The relevant vendored headers currently use:

`LGPL-2.1 OR BSD-2-Clause`

Their SPDX declarations, copyright notices, and attribution must not be
removed.

## Compact kernel type headers

The `vmlinux_compact_*.h` files contain compact kernel type definitions used to
build the BPF program.

They must retain their provenance and any existing notices. They must not be
assumed to be Apache-2.0 merely because they are distributed in this
repository.

Future generated kernel type files should document:

- How they were generated.
- The kernel or BTF source used.
- The generation date or version.
- Any applicable licence and attribution information.

## ASN data

The autonomous-system datasets downloaded from IPtoASN are external data, not
project source code.

IPtoASN distributes its downloadable database under the Public Domain
Dedication and License, version 1.0, identified as `PDDL-1.0`.

The source and licence of redistributed ASN datasets must be documented in the
release package.

## Go dependencies

Dependencies listed in `go.mod` and `go.sum` retain their own licences.

Their presence does not change the licence of project-owned source code.
Binary distributions must preserve any notices required by those dependency
licences.

## Distribution requirements

Source and binary distributions should include:

- The Apache License, Version 2.0.
- This `LICENSING.md` file.
- `THIRD_PARTY_NOTICES.md`.
- Required third-party licence and attribution notices.
- Original copyright notices.
- Clear indications where inherited files have been modified.

## Contribution policy

New project-owned Go code, tests, workflows, and documentation should use the
SPDX identifier `Apache-2.0`.

New BPF source must use an explicitly reviewed SPDX licence identifier that is
compatible with the helpers, program types, and kernel interfaces it uses.

Code copied or substantially adapted from another project must not be merged
until its licence obligations and attribution requirements have been reviewed.
