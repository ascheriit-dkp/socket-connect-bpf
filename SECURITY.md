# Security Policy

## Supported versions

Until the first stable v2 release is published, security fixes are provided
only for the latest revision of the `v2` branch.

| Version or branch | Supported |
|-------------------|-----------|
| `v2`              | Yes       |
| `master`          | No        |
| Older revisions   | No        |

The `master` branch contains the legacy implementation and is retained for
historical reference. It does not receive security fixes.

After stable releases begin, this table will be updated to identify the
supported release series.

## Reporting a vulnerability

Do not report suspected vulnerabilities through public GitHub issues,
discussions, pull requests, or other public channels.

Use GitHub's private vulnerability reporting feature:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.
4. Complete and submit the private report.

A useful report should include:

- A clear description of the suspected vulnerability.
- The affected branch, commit, release, or artifact.
- The Linux distribution, kernel version, architecture, and Go version when
  relevant.
- The exact command-line options and configuration used.
- Reproduction steps or a minimal proof of concept.
- The security impact and realistic attack scenario.
- Relevant logs, traces, stack output, or diagnostic information.
- Any suggested mitigation or fix.
- Whether the issue has been disclosed to anyone else.

Remove passwords, access tokens, private keys, personal data, and unrelated
sensitive information before attaching logs or files.

## Security-relevant issues

Examples of issues that may be security relevant include:

- Privilege escalation or an escape from expected kernel or process isolation.
- Unsafe eBPF behavior that can crash, corrupt, or destabilize a supported
  system.
- Memory-safety or bounds-checking defects in kernel-facing code.
- Incorrect parsing of kernel events that could cause unsafe behavior.
- Bypass of documented PID, UID, address-family, or destination-port filters.
- Exposure of sensitive process, user, network, or command-line information
  beyond the documented behavior.
- Terminal-control or output-injection vulnerabilities not neutralized by the
  output sanitization layer.
- Malicious ASN data or packaged content causing code execution, arbitrary
  file access, or unsafe path handling.
- Release artifacts containing unexpected executables, files, or modified
  dependencies.
- Dependency vulnerabilities that are exploitable through this project.

Ordinary bugs, documentation mistakes, expected root-level visibility, and
behavior already described in the documentation are generally not security
vulnerabilities unless they create an additional security impact.

## Response process

The project aims to:

- Acknowledge a complete report within five business days.
- Provide an initial assessment or request additional information within
  fourteen business days.
- Keep the reporter informed when the assessment materially changes.
- Coordinate remediation and disclosure when the report is confirmed.

These are response targets rather than guarantees. Complex kernel, eBPF,
dependency, or distribution-specific issues may require additional time.

Reports may be closed when they cannot be reproduced, are outside the
supported versions, describe documented behavior without additional security
impact, or do not provide enough information for investigation.

## Coordinated disclosure

Please keep the report and its technical details private until a fix or
mitigation has been released and coordinated disclosure has been agreed.

When a vulnerability is confirmed, the project may:

- Prepare a private fix and regression tests.
- Request a CVE through GitHub Security Advisories when appropriate.
- Publish affected-version and mitigation information.
- Credit the reporter, unless anonymity is requested.
- Coordinate timing with affected upstream projects, dependencies, or Linux
  distributions.

Do not test against systems, networks, accounts, or data that you do not own
or have explicit authorization to assess.

## Research guidelines

Good-faith security research should:

- Use systems and data owned by the researcher or explicitly authorized for
  testing.
- Avoid privacy violations, service disruption, persistence, destructive
  actions, and unnecessary access to data.
- Stop testing and report promptly when sensitive data or unexpected access is
  encountered.
- Collect only the information required to demonstrate the issue.
- Allow reasonable time for investigation and remediation before disclosure.

This policy does not authorize activity that would otherwise be unlawful and
does not provide permission to test third-party systems.
