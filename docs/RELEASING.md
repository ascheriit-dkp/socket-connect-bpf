# Releasing socket-connect-bpf

## Version convention

Releases use Semantic Versioning and tags of the form:

```text
vMAJOR.MINOR.PATCH
```

The first stable v2 release is `v2.0.0`.

Release tags must point to commits on the `v2` branch. The historical `master` branch is not a release source for v2 and must not be merged into or used as the tag target.

## Binary version metadata

Every build embeds:

- version;
- source commit SHA;
- source commit date.

Display it with:

```bash
./socket-connect-bpf --version
```

Normal development builds use version `devel`. The release workflow injects the exact release tag, tagged commit SHA, and tagged commit date.

## Automated release workflow

Pushing a valid release tag starts `.github/workflows/release.yml`.

The workflow rejects a tag unless:

- it matches `vMAJOR.MINOR.PATCH` exactly;
- its commit is reachable from `origin/v2`;
- the checked-out source matches the tagged commit.

The workflow then:

1. builds and tests amd64 and arm64 binaries with exact release metadata;
2. verifies the amd64 `--version` output;
3. creates and verifies deterministic release archives twice;
4. generates SPDX JSON SBOMs for the amd64 and arm64 binaries;
5. creates GitHub build-provenance attestations for the release archives;
6. creates SBOM attestations for both binaries;
7. creates a draft GitHub Release with the archives, checksums, and SBOMs;
8. downloads the draft assets and verifies checksums plus packaged `--version`;
9. publishes the release as Latest;
10. downloads the published assets again and repeats checksum and version verification.

The GitHub Release command uses `--verify-tag`; it will not silently create a missing tag from the repository default branch.

## Creating v2.0.0

After the release-preparation PR is merged and `v2` CI is green:

```bash
git fetch origin
git switch v2
git pull --ff-only origin v2
git tag -a v2.0.0 -m "socket-connect-bpf v2.0.0"
git push origin v2.0.0
```

Do not retarget or force-move a published release tag.

## Release assets

A stable release publishes:

```text
socket-connect-bpf-linux-amd64.tar.gz
socket-connect-bpf-linux-arm64.tar.gz
SHA256SUMS
socket-connect-bpf-linux-amd64.spdx.json
socket-connect-bpf-linux-arm64.spdx.json
```

`SHA256SUMS` covers the executable archives. Each archive also has GitHub artifact provenance, and each architecture-specific binary has an SBOM attestation.

## Verification

Verify downloaded archives with:

```bash
sha256sum --check SHA256SUMS
```

GitHub artifact attestations can also be verified with GitHub CLI, for example:

```bash
gh attestation verify socket-connect-bpf-linux-amd64.tar.gz \
  -R ascheriit-dkp/socket-connect-bpf
```

Release-level attestation verification is also available through current GitHub CLI releases:

```bash
gh release verify v2.0.0 \
  -R ascheriit-dkp/socket-connect-bpf
```
