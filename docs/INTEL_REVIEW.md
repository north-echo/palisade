# Intel Review

This is the operating procedure for promoting external research signals into PALISADE.

## Goal

Keep the process lightweight:

- external projects can produce useful candidate intel
- PALISADE can benefit from it continuously
- operator-facing behavior does not change without review

## Workflow

1. Export candidate artifacts from the research project.
2. Copy them into a review location.
3. Validate them:

```bash
python3 tools/intel_validate.py intel/*.json
```

4. Diff them against the last reviewed snapshot:

```bash
python3 tools/intel_diff.py previous/vendor_priority.json intel/vendor_priority.json
```

5. Review each candidate and decide:

- ignore
- backlog only
- create or update fixture
- create or update matcher
- create or update signature
- save for future `harden` content

6. Promote only curated outputs into PALISADE-owned datasets, tests, docs, or backlog items.

## Promotion Rules

Promote an item only if:

- the intended use is concrete
- the evidence source is recorded
- the confidence is explicit
- the item will not create false certainty in PALISADE output

## Examples

- `vendor_priority.json`
  Good for deciding which platforms to support next
- `platform_patterns.json`
  Good for creating matcher fixtures and new detection logic
- `advisory_watchlist.json`
  Good for watch coverage, signature backlog, and source planning
- `default_creds_candidates.json`
  Good for future `harden` content, not current `edge-audit`

## Anti-Goals

Do not:

- auto-merge external intel into signatures
- treat raw telemetry as direct PALISADE findings
- let research repos define PALISADE behavior without review
