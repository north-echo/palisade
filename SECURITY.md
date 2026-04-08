# Security Policy

PALISADE is a pre-release security tool. If you believe you have found a vulnerability in PALISADE itself, report it privately.

## Scope

This policy covers vulnerabilities in:

- the PALISADE codebase
- packaged releases and build artifacts produced from this repository
- repository-owned demo, validation, and reporting workflows

This policy does not cover:

- vulnerabilities in third-party software or services unless PALISADE introduces the issue through its own code or packaging
- CVEs detected by PALISADE in scanned infrastructure
- general support questions or feature requests

## Supported Versions

PALISADE is currently pre-release. Security fixes will be made on the active `main` branch and included in the next tagged release.

Until a stable release process is established, assume only the latest commit on `main` and the most recent tagged release are supported for security fixes.

## Reporting A Vulnerability

Do not open a public GitHub issue for an undisclosed vulnerability.

Use one of these private reporting paths:

1. GitHub Private Vulnerability Reporting or a private GitHub Security Advisory, if enabled for the repository
2. Direct private contact with the repository maintainer

If you are reporting through GitHub, include `security` in the title so the report is easy to triage.

## What To Include

Please include as much of the following as you can:

- affected version, commit, or branch
- environment details
- concise impact statement
- reproduction steps
- proof-of-concept or test case, if safe to share
- suspected root cause
- any known mitigations or workarounds

If the issue relates to scan behavior, include whether it affects:

- KEV sync and source ingestion
- fingerprinting and signature matching
- report generation or bundle export/import
- demo or validation tooling

## Disclosure Expectations

Please allow time for triage and remediation before public disclosure.

The target process is:

1. Initial acknowledgment within 5 business days
2. Triage and severity assessment as quickly as practical
3. Fix development and validation
4. Coordinated disclosure with release notes and CVE information when appropriate

If PALISADE maintainers determine that a CVE is warranted, the fix release and disclosure note should include:

- affected versions
- impact summary
- remediation guidance
- credit to the reporter, if requested

## Safe Harbor

Good-faith security research intended to identify and privately report vulnerabilities in this repository is welcome.

Please avoid:

- disrupting systems or data you do not own or have permission to test
- accessing, modifying, or exfiltrating non-public data
- using PALISADE against third-party infrastructure without authorization

## CVE Handling

If a vulnerability in PALISADE receives a CVE:

- the changelog should note the fix
- release notes should describe impact and remediation
- the security advisory should link the affected fix commit or release tag

## Detected CVEs In User Environments

PALISADE may identify likely exposure to known exploited vulnerabilities in scanned environments. Those findings are not security reports against PALISADE itself.

For those cases:

- use PALISADE reports for operator triage and remediation planning
- validate high-impact findings through normal operational and vendor channels
- do not file PALISADE repository security reports for target-environment CVEs unless the issue is a bug in PALISADE's detection logic
