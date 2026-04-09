# Intel Handoff

PALISADE can benefit from adjacent research projects such as honeypots, exposure studies, and internal analysis pipelines. That intel should flow into PALISADE through a curated handoff, not through direct runtime coupling.

## Purpose

This handoff model keeps a clean separation between:

- research-grade raw telemetry and experiments
- operator-facing curated PALISADE data

The goal is to let projects such as `ICS-Honeypot` inform PALISADE's upgrades without turning PALISADE into a sink for unreviewed telemetry.

## Recommended Model

Use a one-way flow:

1. External research project produces candidate intel artifacts.
2. A human reviews, filters, and normalizes those artifacts.
3. Approved items are promoted into PALISADE-owned datasets, signatures, docs, or roadmap priorities.

## What PALISADE Should Consume

The recommended handoff artifacts are:

- `vendor_priority.json`
  Used for roadmap prioritization and detection expansion decisions
- `advisory_watchlist.json`
  Used for KEV-source planning, signature curation, and vendor watch coverage
- `platform_patterns.json`
  Used for future matcher improvements and fixture creation
- `default_creds_candidates.json`
  Used for future `harden` or operator-guidance modules, not current `edge-audit`

Templates for these artifacts live under [`intel/`](../intel).

## What Should Stay Outside PALISADE

PALISADE should not directly ingest:

- raw honeypot event streams
- campaign clustering outputs as operator findings
- unreviewed threat labels
- unverified exploit claims

Those may be valid research outputs, but they are not operator-ready PALISADE artifacts.

## Promotion Rules

Before external intel is promoted into PALISADE:

- the source should be recorded
- the intended PALISADE use should be explicit
- confidence should be stated
- the data should be scoped to a concrete use case
- anything user-facing should be phrased conservatively

## Suggested Mapping

Use this rough mapping:

- `vendor_priority.json`
  Drives roadmap and backlog decisions
- `advisory_watchlist.json`
  Feeds signature work, KEV source expansion, and vendor tracking
- `platform_patterns.json`
  Feeds matcher logic, fixtures, and future validation cases
- `default_creds_candidates.json`
  Feeds future hardening and remediation content

## Good Uses

- deciding which edge vendors or platforms to support next
- deciding which CVEs or advisories deserve deeper signature coverage
- capturing recurring HTTP, TLS, or banner patterns worth turning into fixtures
- building future hardening datasets from reviewed default-credential research

## Bad Uses

- treating honeypot observations as direct PALISADE findings
- automatically generating vulnerability signatures from telemetry
- mixing attacker telemetry with operator scan output
- letting external repos define PALISADE behavior without review

## Review Checklist

Before promoting a handoff artifact into PALISADE, ask:

1. Is the source recorded and intelligible?
2. Is the intended PALISADE use concrete?
3. Is the confidence level explicit?
4. Would using this create false certainty in operator output?
5. Should this stay as roadmap intel instead of product data?
