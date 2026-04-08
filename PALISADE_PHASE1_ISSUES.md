# PALISADE Phase 1 Issue List

This document converts [PALISADE_SPEC.md](./PALISADE_SPEC.md) into a practical Phase 1 implementation backlog.

The goal is not to mirror every line of the spec. The goal is to produce a short set of issues that can be opened as GitHub tickets, assigned, and closed with clear acceptance checks.

## Phase 1 Outcome

Phase 1 is complete when PALISADE can:

- Sync and cache KEV data locally
- Fingerprint a bounded set of supported edge-device families using non-intrusive probes
- Match observed product/version evidence against a curated signature set
- Produce text, JSON, and HTML reports
- Persist scan history for later review

Phase 1 does not include:

- Authenticated collection
- Passive monitoring
- SNMP support
- Exploit validation
- Cross-scan diffing

## Milestone Structure

Use one GitHub milestone: `Phase 1 - Edge Audit MVP`

Suggested labels:

- `phase1`
- `epic`
- `cli`
- `db`
- `kev`
- `fingerprinting`
- `signatures`
- `scanner`
- `reporting`
- `testing`
- `docs`

## Epic 1: Repository Scaffolding

### Issue 1.1: Create Python package and CLI skeleton

**Purpose**

Create the initial package layout, CLI entrypoint, and command group structure.

**Scope**

- Add `pyproject.toml`
- Create `src/palisade/`
- Add `cli.py`
- Register commands:
  - `palisade --version`
  - `palisade kev-sync`
  - `palisade edge-audit`
  - `palisade report`

**Dependencies**

- None

**Acceptance checks**

- `pip install -e .` succeeds
- `palisade --help` renders without error
- `palisade --version` prints a version string

### Issue 1.2: Add CI, linting, typing, and test harness

**Purpose**

Set project quality gates early so later work lands into a stable baseline.

**Scope**

- Add GitHub Actions workflow
- Configure `ruff`
- Configure `mypy`
- Configure `pytest`
- Add coverage reporting

**Dependencies**

- Issue 1.1

**Acceptance checks**

- CI runs on Python 3.9-3.12
- `ruff check` passes
- `mypy` passes
- `pytest` runs in CI even if only placeholder tests exist initially

### Issue 1.3: Add contributor and issue templates

**Purpose**

Set contribution expectations and reduce future project management friction.

**Scope**

- Add `CONTRIBUTING.md`
- Add DCO requirement language
- Add bug report template
- Add feature request template
- Add vendor support request template

**Dependencies**

- None

**Acceptance checks**

- Templates render properly in `.github/ISSUE_TEMPLATE/`
- `CONTRIBUTING.md` explains sign-off requirement clearly

## Epic 2: SQLite Store and KEV Sync

### Issue 2.1: Implement SQLite schema and connection layer

**Purpose**

Create the local persistence model for KEV data, scans, devices, and findings.

**Scope**

- Add `core/db.py`
- Implement schema creation
- Implement connection helper
- Add migration strategy, even if minimal

**Dependencies**

- Issue 1.1

**Acceptance checks**

- Fresh database initializes automatically
- All Phase 1 tables are created
- Re-running initialization is safe

### Issue 2.2: Implement KEV fetch, parse, and upsert

**Purpose**

Ingest CISA KEV data into the local store.

**Scope**

- Add KEV fetcher in `core/kev.py`
- Parse KEV JSON feed
- Upsert vulnerabilities into SQLite
- Persist metadata like last sync and catalog version

**Dependencies**

- Issue 2.1

**Acceptance checks**

- Sync imports KEV records into SQLite
- Re-running sync updates existing records without duplication
- Sync metadata is persisted

### Issue 2.3: Implement `kev-sync` CLI command

**Purpose**

Expose KEV lifecycle operations to operators through a stable CLI.

**Scope**

- `palisade kev-sync`
- `palisade kev-sync --status`
- `palisade kev-sync --export <file>`
- `palisade kev-sync --import <file>`
- `palisade kev-sync --offline`

**Dependencies**

- Issue 2.2

**Acceptance checks**

- Status shows last sync time and record count
- Export produces a usable file
- Import restores data into a fresh local database
- Offline mode does not attempt network access

### Issue 2.4: Implement KEV query helpers

**Purpose**

Support later scanner and reporting logic with reusable query functions.

**Scope**

- Query by vendor
- Query by product
- Query by CVE
- Query edge-focused vendor/product entries

**Dependencies**

- Issue 2.2

**Acceptance checks**

- Query helpers return correct records from fixture-backed tests

## Epic 3: Fingerprinting Engine

### Issue 3.1: Build non-intrusive probe framework

**Purpose**

Create the shared fingerprinting engine used by all vendors.

**Scope**

- Add `DeviceFingerprint` model
- Implement TLS certificate probe
- Implement HTTP header/body probe
- Implement banner grab probe
- Add timeout and error handling

**Dependencies**

- Issue 1.1

**Acceptance checks**

- Probes fail gracefully on timeouts and connection refusal
- Only documented probe types are used
- Confidence field is populated consistently

### Issue 3.2: Implement SonicWall and Fortinet fingerprint modules

**Purpose**

Start with two high-value vendors and prove the module pattern.

**Scope**

- Add `sonicwall.py`
- Add `fortinet.py`
- Implement vendor/product indicators
- Implement best-effort version extraction

**Dependencies**

- Issue 3.1

**Acceptance checks**

- Fixture data maps to expected vendor/product results
- Version extraction returns confidence-scored results where possible

### Issue 3.3: Implement F5 and Cisco fingerprint modules

**Purpose**

Expand support to additional common edge-device families.

**Scope**

- Add `f5.py`
- Add `cisco.py`

**Dependencies**

- Issue 3.1

**Acceptance checks**

- Fixture data maps to expected vendor/product results

### Issue 3.4: Implement Palo Alto and Ivanti fingerprint modules

**Purpose**

Complete the initial supported vendor set.

**Scope**

- Add `paloalto.py`
- Add `ivanti.py`

**Dependencies**

- Issue 3.1

**Acceptance checks**

- Fixture data maps to expected vendor/product results

### Issue 3.5: Document confidence model and probe guarantees

**Purpose**

Make the scanner’s claims explicit and defensible.

**Scope**

- Define `high`, `medium`, `low`
- Document what counts as vendor-only, product-level, and version-level evidence
- Document non-intrusive behavior guarantees

**Dependencies**

- Issue 3.1

**Acceptance checks**

- Confidence rules are implemented and documented consistently

## Epic 4: Signature Database and Version Matching

### Issue 4.1: Define signature schema and loader

**Purpose**

Create the curated matching layer between observed device evidence and KEV-relevant exposures.

**Scope**

- Add `edge_audit/signatures/kev_edge.json`
- Add signature loader
- Support query by vendor/product and CVE
- Support custom signature file path

**Dependencies**

- Issue 1.1

**Acceptance checks**

- Signatures load from packaged JSON
- Custom signature file can be loaded

### Issue 4.2: Implement vendor-specific version comparison

**Purpose**

Normalize product version strings enough to support curated KEV matching.

**Scope**

- Add `core/version.py`
- Implement comparison helpers
- Add vendor-specific parsers for initial vendor set

**Dependencies**

- Issue 4.1

**Acceptance checks**

- Known affected/unaffected version pairs pass tests

### Issue 4.3: Create starter signature set

**Purpose**

Ship a usable initial dataset rather than an empty framework.

**Scope**

- Add 15-30 initial signatures
- Cover supported vendors as far as reliable data allows
- Record rationale for any vendor/product gaps

**Dependencies**

- Issue 4.1
- Issue 4.2

**Acceptance checks**

- Starter set covers the supported vendors with documented caveats
- Signatures validate against schema expectations

## Epic 5: Edge Audit Scanner

### Issue 5.1: Implement target parsing and scan lifecycle

**Purpose**

Create the scanner orchestration path independent of matching quality.

**Scope**

- Add `edge_audit/scanner.py`
- Parse single IP, CIDR, comma-separated targets, and target file input
- Create and update scan records in SQLite

**Dependencies**

- Issue 2.1
- Issue 3.1

**Acceptance checks**

- Scanner persists scan start/completion state
- Target enumeration works for all supported input styles

### Issue 5.2: Integrate fingerprinting and signature matching

**Purpose**

Turn raw probes into stored devices and findings.

**Scope**

- Run probe workflow per target
- Resolve vendor/product/version evidence
- Match against signatures
- Persist devices and findings

**Dependencies**

- Issue 3.2
- Issue 3.3
- Issue 3.4
- Issue 4.3
- Issue 5.1

**Acceptance checks**

- Findings are stored for positive matches
- Discovery-only mode stores device evidence without findings

### Issue 5.3: Add scanner CLI options

**Purpose**

Expose the minimum useful operator workflow through the CLI.

**Scope**

- `--target`
- `--target-file`
- `--discover`
- `--vendor`
- `--ports`
- `--timeout`
- `--concurrency`
- `--output`
- `--report`
- `--cpg-map`
- `--history`
- `--scan-id`

**Dependencies**

- Issue 5.2

**Acceptance checks**

- Options parse and drive the expected behavior
- Invalid combinations fail with readable errors

### Issue 5.4: Add progress and summary output

**Purpose**

Make the scanner usable in a terminal during longer runs.

**Scope**

- Rich progress bar
- Findings summary
- Completion statistics

**Dependencies**

- Issue 5.2

**Acceptance checks**

- Terminal output remains readable during single-host and subnet scans

## Epic 6: Reporting and CPG Mapping

### Issue 6.1: Implement CPG mapping model

**Purpose**

Attach findings to the project’s compliance-oriented framing without overstating control satisfaction.

**Scope**

- Add `core/cpg.py`
- Define Phase 1 mappings
- Ensure edge-audit findings primarily map to `1.A`

**Dependencies**

- Issue 5.2

**Acceptance checks**

- Findings can render associated CPG IDs
- Report wording distinguishes likely exposure from confirmed remediation status

### Issue 6.2: Implement text and JSON reporting

**Purpose**

Deliver the fastest useful outputs first.

**Scope**

- Add text report renderer
- Add JSON report renderer
- Include scan metadata, device inventory, findings, remediation, and CPG mapping

**Dependencies**

- Issue 6.1

**Acceptance checks**

- Text output is readable in an 80-column terminal
- JSON output is stable and testable

### Issue 6.3: Implement HTML reporting

**Purpose**

Produce a portable artifact for operators to share with leadership or regulators.

**Scope**

- Add self-contained HTML report
- No external assets

**Dependencies**

- Issue 6.2

**Acceptance checks**

- HTML report opens locally and prints cleanly

### Issue 6.4: Implement `report` CLI command

**Purpose**

Allow reports to be generated independently from scan execution.

**Scope**

- `palisade report --scan-id <uuid>`
- `palisade report --latest`
- `--format`
- `--output`

**Dependencies**

- Issue 6.2
- Issue 6.3

**Acceptance checks**

- Reports can be generated from persisted scan history

## Epic 7: Tests and Fixtures

### Issue 7.1: Add fixture corpus

**Purpose**

Create stable non-live inputs for vendor matching and report tests.

**Scope**

- Sample banners
- Sample HTTP responses
- Sample TLS certificate data
- KEV sample JSON

**Dependencies**

- None

**Acceptance checks**

- Fixtures exist for each supported vendor module

### Issue 7.2: Add unit tests for KEV, versions, and signatures

**Purpose**

Validate core logic before scanner integration grows.

**Scope**

- `test_kev.py`
- `test_version.py`
- `test_signatures.py`

**Dependencies**

- Issue 2.4
- Issue 4.2

**Acceptance checks**

- Core parsing and comparison logic passes under fixtures

### Issue 7.3: Add fingerprinting and scanner integration tests

**Purpose**

Prove the main operator workflow without live network dependencies.

**Scope**

- `test_device.py`
- `test_scanner.py`
- Mock network I/O

**Dependencies**

- Issue 5.2

**Acceptance checks**

- No live network access is required
- Happy path and failure path coverage exist

### Issue 7.4: Add report tests and coverage gate

**Purpose**

Keep output stable and hold the codebase to the Phase 1 quality bar.

**Scope**

- `test_report.py`
- Add coverage gate in CI

**Dependencies**

- Issue 6.4

**Acceptance checks**

- Coverage is at least 80%
- Report renderers have snapshot or schema-backed tests

## Epic 8: Operator Documentation

### Issue 8.1: Write Getting Started guide

**Purpose**

Help a non-specialist operator run a first scan successfully.

**Scope**

- Prerequisites
- Install steps
- First scan walkthrough
- Expected output
- FAQ

**Dependencies**

- Issue 5.3
- Issue 6.2

**Acceptance checks**

- Commands are copy-paste functional against the implemented CLI

### Issue 8.2: Write Edge Audit guide

**Purpose**

Explain what the scanner does, how to interpret confidence, and where the boundaries are.

**Scope**

- Supported vendors
- Detection methods
- Confidence interpretation
- Air-gapped usage

**Dependencies**

- Issue 5.2
- Issue 6.1

**Acceptance checks**

- No unexplained jargon remains

### Issue 8.3: Write signatures and compliance mapping docs

**Purpose**

Document how matching data is maintained and how output relates to CPGs.

**Scope**

- `docs/SIGNATURES.md`
- `docs/CPG_MAPPING.md`
- Optional regulator-facing note if time permits

**Dependencies**

- Issue 4.3
- Issue 6.1

**Acceptance checks**

- Contributors can add or extend signatures using the documented format

## Recommended Build Order

Follow this order unless a dependency forces otherwise:

1. Issue 1.1
2. Issue 1.2
3. Issue 2.1
4. Issue 2.2
5. Issue 2.3
6. Issue 7.1
7. Issue 3.1
8. Issues 3.2, 3.3, 3.4
9. Issue 4.1
10. Issue 4.2
11. Issue 4.3
12. Issue 5.1
13. Issue 5.2
14. Issue 5.3
15. Issue 6.1
16. Issue 6.2
17. Issue 6.3
18. Issue 6.4
19. Issues 7.2, 7.3, 7.4
20. Issues 8.1, 8.2, 8.3

## MVP Exit Criteria

Treat Phase 1 as done when all of the following are true:

- A fresh clone can install and run the CLI
- KEV sync works and persists locally
- At least one supported vendor fixture per vendor family passes fingerprinting tests
- Signature matching produces stored findings from fixture-backed scanner tests
- Text, JSON, and HTML reports generate from persisted scans
- CI is green
- Coverage is at least 80%
- The README and operator docs still match the implemented behavior
