# Architecture Overview

PALISADE is built as a local-first pipeline for edge-device exposure triage.

## Core Flow

1. KEV data is synced into a local SQLite database.
2. Targets are probed with non-intrusive HTTP, TLS, and banner collection.
3. Vendor matchers classify likely devices and extract version evidence when possible.
4. Version-aware signatures are matched against the collected fingerprints.
5. Findings, provenance, and scan history are stored locally.
6. Reports, diffs, and portable bundles are generated from the stored scan data.

## Major Components

- `src/palisade/core/db.py`
  Local schema creation, persistence, and additive migrations
- `src/palisade/core/kev.py`
  KEV record normalization, sync, import, and query logic
- `src/palisade/core/kev_sources.py`
  Source adapter layer for CISA and supplemental exploited-vulnerability feeds
- `src/palisade/core/device.py`
  Non-intrusive probe collection and raw fingerprint handling
- `src/palisade/edge_audit/vendors/`
  Vendor-specific fingerprint matchers
- `src/palisade/core/version.py`
  Vendor-aware version normalization and comparison
- `src/palisade/edge_audit/signatures/`
  Curated edge-focused KEV signature set
- `src/palisade/edge_audit/scanner.py`
  Scan orchestration, persistence, finding generation, history, and diffs
- `src/palisade/core/report.py`
  Text, JSON, and HTML reporting
- `src/palisade/core/artifact.py`
  Export and import of portable scan bundles

## Design Principles

- local-first by default
- operator-readable outputs
- non-intrusive collection
- explicit source provenance
- narrow Phase 1 scope

## Important Boundaries

- PALISADE is not trying to prove exploitability.
- PALISADE is not trying to become a full OT monitoring platform.
- PALISADE treats source provenance and confidence as part of the result, not as incidental metadata.
