# Changelog

All notable changes to PALISADE will be documented in this file.

The format is intentionally simple and release-oriented.

## [0.1.0] - 2026-04-08

Initial Phase 1 MVP baseline.

### Added

- Local SQLite-backed KEV store and sync flow
- CISA KEV ingestion plus supplemental-source support
- Source-aware findings and reporting
- Edge-device fingerprinting for:
  - SonicWall
  - Fortinet
  - F5
  - Cisco
  - Palo Alto
  - Ivanti
  - Citrix
- Version-aware KEV signature matching
- Text, JSON, and HTML reports
- Scan history, filtering, and scan diffs
- Scan bundle export/import
- JSON config support
- Fixture-backed demo environment
- Replay-lab validation helpers

### Notes

- This release remains best-effort and unauthenticated by design.
- Validation is strongest for HTTP fixture-backed flows; TLS and banner validation remain lighter.
