# PALISADE Implementation Specification

**Practical Audit Library for Industrial Security, Asset Discovery, and Edge Defense**

Version: 1.0
Author: Christopher Lusk <clusk@northecho.dev>
Assisted-by: Claude (Anthropic)
Date: 2026-04-08

---

## 1. Overview

PALISADE is a free, open-source OT security baseline toolkit targeting small and mid-size utilities, municipal systems, and critical infrastructure operators. It provides executable security tools — scripts, checklists, and templates — that a single IT/OT operator can use without specialized security expertise or commercial platform licenses.

This specification defines the implementation plan for Phase 1: the `edge-audit` module. Phase 1 is intentionally narrow: **best-effort, unauthenticated, non-intrusive exposure triage** for edge network devices using CISA KEV-derived signatures plus vendor/product fingerprinting evidence.

### 1.0 Phase 1 Outcome

At the end of Phase 1, PALISADE should be able to:

- Sync and cache KEV data locally
- Fingerprint a bounded set of supported edge-device families using non-intrusive probes
- Match observed product/version evidence against a curated signature set
- Produce operator-readable and machine-readable reports
- Persist scan history for later review

Phase 1 does not need to prove exploitability, guarantee version accuracy on every vendor, or satisfy every planned reporting and workflow convenience feature.

### 1.1 Design Constraints

- **Python 3.9+**, Click CLI, Rich console output
- **SQLite** for local KEV cache and scan history
- **No external services required at runtime** (offline-capable after initial KEV/signature sync)
- **Podman-native testing** (rootless, no Docker dependency)
- **Non-intrusive scanning only** — no exploitation, no authentication, no disruptive probes
- **Best-effort versioning only** — authoritative version validation is out of scope without authenticated access
- **Evidence-generating** — all output suitable for compliance documentation

### 1.2 Repository

- GitHub: `north-echo/palisade`
- License: Apache 2.0
- Commit convention: `Signed-off-by: Christopher Lusk <clusk@northecho.dev>` / `Assisted-by: Claude (Anthropic)`

### 1.3 Explicitly Out Of Scope For Phase 1

- Authenticated collection from management APIs
- Passive network monitoring
- SNMP-based identification
- Exploit checks or validation
- Cross-scan diffing and advanced reporting workflows
- Broad asset inventory outside the supported edge-device focus

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────┐
│                   CLI (Click)                    │
│            palisade [command] [options]           │
└──────────┬──────────┬──────────┬────────────────┘
           │          │          │
    ┌──────▼──┐ ┌─────▼────┐ ┌──▼──────────┐
    │kev-sync │ │edge-audit│ │  report      │
    │         │ │          │ │              │
    │ Fetch   │ │ Discover │ │ Text/JSON/   │
    │ Parse   │ │ Finger-  │ │ HTML output  │
    │ Store   │ │ print    │ │ CPG mapping  │
    └────┬────┘ │ Match    │ └──────────────┘
         │      └────┬─────┘
    ┌────▼───────────▼─────┐
    │     SQLite Store      │
    │  kev.db               │
    │  ├── vulnerabilities  │
    │  ├── scans            │
    │  ├── findings         │
    │  └── devices          │
    └───────────────────────┘
```

### 2.2 Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `cli.py` | Click command group, global options (--verbose, --output-format, --db-path) |
| `core/kev.py` | Fetch CISA KEV JSON, parse, upsert into SQLite, query by vendor/product |
| `core/device.py` | Service fingerprinting engine — banner grab, TLS cert inspection, HTTP header analysis |
| `core/report.py` | Report generation in text (Rich tables), JSON, and HTML formats |
| `core/cpg.py` | CPG mapping definitions and report annotations |
| `core/db.py` | SQLite connection management, schema migrations, query helpers |
| `edge_audit/scanner.py` | Orchestrator — target enumeration, vendor dispatch, finding collection |
| `edge_audit/vendors/*.py` | Per-vendor fingerprinting and best-effort version extraction logic |
| `edge_audit/signatures/kev_edge.json` | Static mapping of KEV CVE IDs to vendor/product/version ranges |

---

## 3. Work Packages

### WP-1: Project Scaffolding

**Goal:** Repository structure, packaging, CLI skeleton, CI.

**Tasks:**
1. Initialize repo with pyproject.toml (project name: `palisade`, entry point: `palisade`)
2. Create package structure under `src/palisade/`
3. Implement Click CLI skeleton with command group:
   - `palisade --version`
   - `palisade --help`
   - `palisade kev-sync`
   - `palisade edge-audit`
   - `palisade report`
4. Create GitHub Actions CI workflow:
   - Lint (ruff)
   - Type check (mypy)
   - Test (pytest)
   - Supported Python: 3.9, 3.10, 3.11, 3.12
5. Create CONTRIBUTING.md with DCO requirement
6. Create .github/ISSUE_TEMPLATE/ (bug report, feature request, vendor request)

**Deliverables:** Working `pip install -e .` with `palisade --help` functional.

**Acceptance criteria:**
- `palisade --version` prints version string
- CI passes on all supported Python versions
- `ruff check` and `mypy` pass clean

---

### WP-2: SQLite Store and KEV Sync

**Goal:** Local KEV database with sync capability.

**Schema:**

```sql
CREATE TABLE kev_vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT NOT NULL,
    product TEXT NOT NULL,
    vulnerability_name TEXT NOT NULL,
    date_added TEXT NOT NULL,
    short_description TEXT,
    required_action TEXT,
    due_date TEXT,
    known_ransomware_use TEXT,
    notes TEXT,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_kev_vendor ON kev_vulnerabilities(vendor_project);
CREATE INDEX idx_kev_product ON kev_vulnerabilities(product);
CREATE INDEX idx_kev_date_added ON kev_vulnerabilities(date_added);

CREATE TABLE kev_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Stores: catalog_version, last_sync, total_count

CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,  -- UUID
    started_at TEXT NOT NULL,
    completed_at TEXT,
    target_spec TEXT NOT NULL,  -- original --target argument
    status TEXT NOT NULL DEFAULT 'running',  -- running, completed, failed
    device_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0
);

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,  -- UUID
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    ip_address TEXT NOT NULL,
    port INTEGER,
    vendor TEXT,
    product TEXT,
    version TEXT,
    fingerprint_method TEXT,  -- banner, tls_cert, http_header
    raw_fingerprint TEXT,     -- raw banner/header for audit trail
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_devices_scan ON devices(scan_id);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,  -- UUID
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    cve_id TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version_detected TEXT,
    version_fixed TEXT,        -- from signature data
    confidence TEXT NOT NULL,  -- high, medium, low
    cpg_ids TEXT,              -- comma-separated CPG references
    remediation TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_cve ON findings(cve_id);
```

**Tasks:**
1. Implement `core/db.py` with connection management, schema creation, migration support
2. Implement `core/kev.py`:
   - `kev_sync()`: Fetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   - Parse and upsert all entries
   - Store catalog version and sync timestamp in kev_meta
   - Support `--offline` flag (use existing local data)
3. Implement `kev-sync` CLI command:
   - `palisade kev-sync` — fetch and update
   - `palisade kev-sync --status` — show last sync time, entry count
   - `palisade kev-sync --export kev.json` — export local cache for USB transfer
   - `palisade kev-sync --import kev.json` — import from file (air-gap support)
4. Implement KEV query functions:
   - `query_by_vendor(vendor)` → list of CVEs
   - `query_by_product(vendor, product)` → list of CVEs
   - `query_by_cve(cve_id)` → full record
   - `query_edge_devices()` → KEV entries matching known edge device vendors/products

**Deliverables:** Working KEV sync with SQLite persistence.

**Acceptance criteria:**
- `palisade kev-sync` fetches and stores KEV catalog
- `palisade kev-sync --status` shows entry count and sync time
- Air-gap import/export round-trips correctly
- All queries return correct results against live KEV data
- Tests use fixture data (snapshot of KEV subset), not live API

---

### WP-3: Device Fingerprinting Engine

**Goal:** Non-intrusive identification of likely edge device vendor, product, and, where possible, version evidence.

**Fingerprinting methods (in priority order):**

1. **TLS Certificate Inspection** — Connect to 443, extract cert CN/SAN, issuer, subject fields. Many appliances use self-signed certs with vendor-specific patterns.
2. **HTTP/HTTPS Response Headers** — `Server`, `X-Powered-By`, custom headers (e.g., SonicWall `SonicWALL`, Fortinet `xxxxxxxx` cookie patterns).
3. **HTTP Response Body Patterns** — Login page HTML contains vendor-specific strings, JavaScript references, image paths.
4. **Banner Grab** — Connect to common management ports (22, 23, 443, 4443, 8443, 10443) and collect service banners.
5. **SNMP (future/optional)** — Excluded from Phase 1. If later added, require explicit opt-in and separate handling.

**Tasks:**
1. Implement `core/device.py`:
   - `DeviceFingerprint` dataclass: ip, port, vendor, product, version, method, raw_data, confidence
   - `fingerprint_host(ip, ports)` → list of DeviceFingerprint
   - `fingerprint_tls(ip, port)` → DeviceFingerprint or None
   - `fingerprint_http(ip, port)` → DeviceFingerprint or None
   - `fingerprint_banner(ip, port)` → DeviceFingerprint or None
2. Implement vendor-specific pattern matching in `edge_audit/vendors/`:
   - Each vendor module exports: `VENDOR_NAME`, `PATTERNS` (compiled regexes for identification), `extract_version(raw_data)` → version string or None
   - `sonicwall.py`: SMA, NSA, TZ, Gen 7 identification. Patterns: `SonicWALL` header, `/auth.html` login page markers, TLS cert CN patterns.
   - `fortinet.py`: FortiGate/FortiOS identification. Patterns: `APSCOOKIE_` cookie, `/remote/login` path, TLS cert patterns.
   - `f5.py`: BIG-IP identification. Patterns: `BIGipServer` cookie, `/tmui/login.jsp` path, `F5` in cert CN.
   - `cisco.py`: ASA/FTD identification. Patterns: `+CSCOE+` WebVPN marker, Cisco cert CN patterns, ASDM markers.
   - `paloalto.py`: PAN-OS identification. Patterns: `/global-protect/login.esp` path, `PanOS` markers.
   - `ivanti.py`: Connect Secure identification. Patterns: `/dana-na/auth/` path, `DSID` cookie patterns.
3. Implement confidence scoring:
   - **High**: Version string explicitly present in banner/response
   - **Medium**: Vendor + product identified but version inferred from behavior/features
   - **Low**: Vendor identified but product/version uncertain
4. Implement timeout and error handling:
   - Connection timeout: 5 seconds (configurable)
   - Read timeout: 10 seconds (configurable)
   - Graceful handling of refused connections, TLS errors, HTTP errors
   - Rate limiting: max 10 concurrent connections (configurable)

**Deliverables:** Working fingerprinting engine with 6 vendor modules.

**Acceptance criteria:**
- Each vendor module matches expected vendor/product indicators from fixture data (sample banners, certs, HTTP responses)
- Version extraction is treated as opportunistic and confidence-scored, not guaranteed
- Confidence scoring is consistent and documented
- Timeouts and errors handled without crashes
- Test coverage demonstrates only the documented HTTP/TLS/banner probes are used

---

### WP-4: KEV-to-Version Signature Database

**Goal:** Mapping layer between KEV CVE entries and affected version ranges for supported edge devices.

**Data structure (`edge_audit/signatures/kev_edge.json`):**

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-08T00:00:00Z",
  "signatures": [
    {
      "cve_id": "CVE-2024-40766",
      "vendor": "sonicwall",
      "product": "SonicOS",
      "product_families": ["NSA", "TZ", "SOHO"],
      "affected_versions": {
        "operator": "lt",
        "version": "5.9.2.14-13o"
      },
      "fixed_version": "5.9.2.14-13o",
      "kev_date_added": "2024-09-09",
      "known_ransomware_use": "Known",
      "severity": "critical",
      "remediation": "Update SonicOS to version 5.9.2.14-13o or later. If immediate patching is not possible, restrict management interface access to trusted networks only.",
      "references": [
        "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015"
      ],
      "cpg_ids": ["1.A"]
    }
  ]
}
```

**Version comparison logic:**
- Semantic version comparison with vendor-specific handling
- Support for operators: `lt` (less than), `le` (less than or equal), `range` (between two versions), `exact` (specific version)
- Vendor-specific version parsing (SonicWall uses `x.x.x.x-xxo` format, Fortinet uses `x.x.x build xxxx`, etc.)

**Tasks:**
1. Create initial `kev_edge.json` with signatures for:
   - A curated starter set for supported vendors, prioritized by date_added and known_ransomware_use
   - Target: 15-30 total signatures across all vendors at launch
2. Implement version comparison logic in `core/version.py`:
   - `parse_version(vendor, version_string)` → normalized comparable version
   - `is_affected(device_version, signature)` → bool
   - Vendor-specific parsers for each supported vendor's versioning scheme
3. Implement signature loading and query in `edge_audit/signatures/loader.py`:
   - Load from JSON file
   - Query by vendor + product
   - Query by CVE ID
   - Support for user-supplied additional signature files (`--signatures /path/to/custom.json`)
4. Document signature format and contribution process in `docs/SIGNATURES.md`

**Deliverables:** Populated signature database with version comparison engine.

**Acceptance criteria:**
- Initial signature set covers the supported vendors with documented rationale for any gaps
- Version comparison correct for all vendor-specific formats (test with known affected/unaffected version pairs)
- Custom signature file loading works
- Signature format documented with examples for contributors

---

### WP-5: Edge Audit Scanner (Orchestrator)

**Goal:** Main scanning workflow that ties fingerprinting, signature matching, and reporting together.

**Tasks:**
1. Implement `edge_audit/scanner.py`:
   - `EdgeAuditScanner` class:
     - `__init__(db, kev_store, signatures, config)`
     - `scan(targets, options)` → ScanResult
     - Target parsing: single IP, CIDR range, comma-separated list, file input (`--target-file`)
   - Scan workflow:
     1. Create scan record in SQLite
     2. Enumerate targets (expand CIDR, resolve hostnames)
     3. For each target: fingerprint → identify vendor/product/version evidence → match against signatures → record findings
     4. Update scan record with completion status and counts
     5. Return ScanResult with all devices and findings
2. Implement `edge-audit` CLI command:
   - `palisade edge-audit --target 192.168.1.1` — single target
   - `palisade edge-audit --target 192.168.1.0/24` — subnet scan
   - `palisade edge-audit --target 192.168.1.0/24 --discover` — discovery mode (fingerprint only, no KEV/signature match)
   - `palisade edge-audit --target-file targets.txt` — file input
   - `palisade edge-audit --vendor sonicwall` — filter to specific vendor
   - `palisade edge-audit --ports 443,4443,8443` — custom port list
   - `palisade edge-audit --timeout 10` — connection timeout
   - `palisade edge-audit --concurrency 5` — max concurrent connections
   - `palisade edge-audit --output json` — output format (text, json, html)
   - `palisade edge-audit --report` — generate full report file
   - `palisade edge-audit --cpg-map` — include CPG mapping in output
3. Implement progress display:
   - Rich progress bar during scanning
   - Live table of findings as discovered
   - Summary statistics at completion
4. Implement scan history:
   - `palisade edge-audit --history` — list previous scans
   - `palisade edge-audit --history --scan-id <uuid>` — show specific scan results

Phase 1 note:
- Scan history listing is in scope.
- Cross-scan diffing is deferred until the core scanner and report model stabilize.

**Deliverables:** Complete edge-audit scanning workflow.

**Acceptance criteria:**
- Single IP, CIDR, and file-based targeting all work
- Findings correctly match curated signatures to fingerprinted devices
- Progress display renders correctly in terminal
- Scan history persists across invocations
- All output formats (text, JSON, HTML) produce valid output

---

### WP-6: Report Generation and CPG Mapping

**Goal:** Compliance-ready output with CISA CPG cross-references.

**Tasks:**
1. Implement `core/report.py`:
   - `TextReport`: Rich-formatted console output with color-coded severity
   - `JSONReport`: Machine-parseable output following a defined schema
   - `HTMLReport`: Self-contained HTML file (inline CSS, no external dependencies) suitable for printing or emailing
   - All reports include: scan metadata, device inventory, findings sorted by severity, remediation guidance, CPG mapping
2. Implement `core/cpg.py`:
   - CPG definitions (ID, title, description, objective)
   - Mapping logic: finding → applicable CPGs
   - CPG coverage summary: which CPGs are addressed, which have gaps

Phase 1 CPG note:
- The primary mapping for `edge-audit` findings is CPG `1.A` (Mitigate Known Exploited Vulnerabilities).
- Report language must distinguish between "potential exposure identified" and "control fully satisfied."

3. Report sections:
   - **Executive Summary**: Devices scanned, findings count by severity, top-priority actions
   - **Device Inventory**: All discovered devices with vendor, product, version, IP
   - **Findings Detail**: Per-finding: CVE ID, device, severity, description, remediation, CPG reference
   - **Remediation Priority**: Ordered action list — what to patch first and why
   - **CPG Compliance Summary**: Table showing CPG coverage status
   - **Appendix: Raw Data**: Scan parameters, timestamps, tool version
4. Implement `report` CLI command:
   - `palisade report --scan-id <uuid> --format html --output report.html`
   - `palisade report --scan-id <uuid> --format json --output report.json`
   - `palisade report --latest --format text` — report on most recent scan

**Deliverables:** Three report formats with CPG mapping.

**Acceptance criteria:**
- HTML report renders correctly in browser and prints cleanly
- JSON report validates against defined schema
- Text report is readable in 80-column terminal
- CPG mapping is accurate per CISA definitions
- Reports include all required sections

---

### WP-7: Testing and Quality

**Goal:** Comprehensive test coverage without requiring live devices.

**Testing strategy:**
- **Unit tests**: All core logic (version comparison, KEV parsing, fingerprinting pattern matching)
- **Integration tests**: Scanner workflow with mocked network responses
- **Fixture data**: Sample banners, HTTP responses, TLS certificates for each supported vendor
- **No live network tests in CI** — all network I/O mocked
- **Optional local validation**: Podman-based manual checks can supplement fixtures but are not CI requirements

**Tasks:**
1. Create test fixtures in `tests/fixtures/`:
   - `banners/` — sample SSH/service banners per vendor
   - `http_responses/` — sample HTTP responses (headers + body) per vendor
   - `tls_certs/` — sample certificate data per vendor
   - `kev_sample.json` — subset of KEV catalog for testing
2. Implement tests:
   - `test_kev.py`: KEV parsing, storage, querying
   - `test_device.py`: Fingerprinting accuracy per vendor
   - `test_version.py`: Version comparison for all vendor formats
   - `test_scanner.py`: End-to-end scan workflow with mocked network
   - `test_report.py`: Report generation for all formats
   - `test_signatures.py`: Signature loading, matching, custom file support
3. Coverage target: 80% minimum for `src/palisade/`
4. CI configuration:
   - pytest with coverage reporting
   - ruff linting
   - mypy type checking
   - Dependabot for dependency updates

**Deliverables:** Test suite with fixtures, CI pipeline.

**Acceptance criteria:**
- All tests pass on Python 3.9–3.12
- Coverage >= 80%
- No live network calls in test suite
- CI pipeline green on all checks

---

### WP-8: Documentation and Operator Guides

**Goal:** Documentation that speaks to the target audience — utility operators, not security engineers.

**Tasks:**
1. `docs/GETTING_STARTED.md`:
   - Prerequisites (plain language)
   - Installation (copy-paste commands)
   - First scan walkthrough with expected output
   - "What to do with results" decision tree
   - FAQ: "Will this break my network?" "Do I need permission?" "What if I find something?"
2. `docs/EDGE_AUDIT.md`:
   - Supported devices with identification details
   - How fingerprinting works (plain language)
   - Understanding results: severity, confidence, remediation
   - Running in air-gapped environments
3. `docs/CPG_MAPPING.md`:
   - What are CISA CPGs and why they matter
   - How PALISADE maps to specific CPGs
   - Using PALISADE output for compliance evidence
4. `docs/SIGNATURES.md`:
   - Signature format specification
   - How to contribute new signatures
   - How to add custom signatures for internal use
5. `docs/FOR_REGULATORS.md`:
   - How PALISADE aligns with AWIA Section 2013, CISA CPGs, NIST CSF
   - Sample language for security assessments referencing PALISADE output

**Deliverables:** Complete documentation suite.

**Acceptance criteria:**
- Getting Started walkthrough tested by someone without security background (or self-tested with "fresh eyes" pass)
- No unexplained jargon — every technical term defined on first use
- All code examples copy-paste functional

---

## 4. Implementation Order

| Phase | Work Packages | Estimated Effort | Dependencies |
|-------|---------------|-----------------|--------------|
| 1 | WP-1 (Scaffolding) | 3-5 hours | None |
| 2 | WP-2 (KEV Sync) | 4-6 hours | WP-1 |
| 3 | WP-3 (Fingerprinting) + WP-4 (Signatures) | 10-16 hours | WP-1 |
| 4 | WP-5 (Scanner) | 6-10 hours | WP-2, WP-3, WP-4 |
| 5 | WP-6 (Reports) | 4-6 hours | WP-5 |
| 6 | WP-7 (Testing) | 6-10 hours | Parallel with WP-3–WP-6 |
| 7 | WP-8 (Docs) | 4-6 hours | WP-5, WP-6 |

**Total estimated: 40–60 hours for a disciplined Phase 1 implementation.**

---

## 5. Future Modules (Post-Phase 1)

These modules are scoped but not specified in detail. Each will get its own implementation spec when prioritized.

### 5.1 net-discover

Lightweight OT network asset discovery:
- Passive traffic analysis (pcap parsing)
- Active service enumeration (nmap integration)
- OT protocol identification (Modbus/TCP, DNP3, EtherNet/IP, BACnet)
- Asset inventory generation with network topology map
- CPG mapping: 5.A (Assets in Inventory), 2.F (Network Monitoring)

### 5.2 harden

Environment-specific hardening checklists:
- Vendor-specific guides (SonicWall, Fortinet, Cisco, common HMI/SCADA platforms)
- Interactive checklist CLI with progress tracking
- Evidence generation (before/after configuration snapshots)
- CPG mapping: 1.E (Segmentation), 2.A (Default Passwords), 2.B (Password Strength)

### 5.3 ir-runbooks

OT incident response templates:
- Scenario-based runbooks (ransomware on SCADA network, compromised edge device, unauthorized OT access, suspicious OT traffic)
- Fill-in-the-blank templates with organization-specific fields
- Decision trees for containment vs. continued operation
- Communication templates (board notification, regulator reporting, CISA incident report)
- CPG mapping: 3.A (Cybersecurity Leadership), 7.A (Incident Reporting), 7.B (IR Plan)

---

## 6. BLEACH Crossover

PALISADE's `edge-audit` module shares target space with BLEACH (BOD-Listed Edge Appliance Compromise Hunter). The relationship:

- **BLEACH** is offensive research tooling — campaign-based recon-to-dynamic-PoC for vulnerability discovery. Private, not public.
- **PALISADE** is defensive operator tooling — known-vulnerability detection for remediation. Public, open-source.

Findings from BLEACH research (after responsible disclosure and patch availability) can feed PALISADE signatures. BLEACH discovers new vulnerabilities; PALISADE helps operators find known ones.

Data flow: BLEACH research → responsible disclosure → vendor patch → CVE/KEV listing → PALISADE signature update.

---

## 7. Community and Outreach

### 7.1 Launch Strategy

1. **Soft launch**: Push to GitHub, announce on personal channels
2. **Community validation**: Share with WaterISAC, state ISACs, CISA regional contacts for feedback
3. **Conference presentation**: Target ICS Village (DEF CON), S4, or BSides Industrial track
4. **Ongoing**: Monthly KEV signature updates, quarterly module releases

### 7.2 Feedback Channels

- GitHub Issues (structured templates)
- GitHub Discussions (open-ended)
- Contact: clusk@northecho.dev

---

*End of specification.*
