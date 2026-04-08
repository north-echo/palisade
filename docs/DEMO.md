# Demo Runbook

Use the fixture-backed demo when you need a clean, repeatable walkthrough without probing live infrastructure.

## Build

```bash
PYTHONPATH=src python3 tools/build_demo.py
```

## Present

1. Show the summary file in `demo/out/SUMMARY.md`
2. Show the latest report in `demo/out/reports/latest-report.txt`
3. Show the diff report in `demo/out/reports/diff-report.txt`
4. Show the bundle artifact in `demo/out/bundles/`
5. Re-import the bundle into a fresh database if you want to demonstrate portability

## What The Demo Illustrates

- CISA KEV ingestion
- supplemental-source ingestion
- source-aware findings
- scan history and diffing
- report generation
- bundle export/import

## What It Does Not Illustrate

- live network behavior
- unauthenticated probe timing
- edge cases in vendor fingerprinting on real appliances

For those, use a controlled lab validation pass after the demo workflow is stable.
