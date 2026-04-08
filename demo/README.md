# Demo Environment

This demo is fixture-backed. It does not scan real appliances. It builds a local SQLite database, two seeded scans, reports, and a scan bundle so you can show the PALISADE workflow end to end without network dependencies.

## Build The Demo

```bash
PYTHONPATH=src python3 tools/build_demo.py
```

By default this writes to `demo/out/`.

## What You Get

- `demo/out/palisade-demo.db`
- `demo/out/palisade.demo.json`
- `demo/out/reports/latest-report.txt`
- `demo/out/reports/diff-report.txt`
- `demo/out/bundles/<scan-id>.zip`
- `demo/out/SUMMARY.md`

## Suggested Walkthrough

1. Show the generated summary:

```bash
cat demo/out/SUMMARY.md
```

2. Show the latest report:

```bash
cat demo/out/reports/latest-report.txt
```

3. Show the diff between scans:

```bash
cat demo/out/reports/diff-report.txt
```

4. Show that the bundle can be re-imported:

```bash
PYTHONPATH=src python3 -m palisade --db-path demo/imported.db scan-import --input demo/out/bundles/<scan-id>.zip
PYTHONPATH=src python3 -m palisade --db-path demo/imported.db edge-audit --history
```

## Demo Story

The seeded scenario shows:

- An older Fortinet device appearing in the baseline scan and resolved in the latest scan
- A SonicWall finding that persists across scans
- A Citrix finding introduced in the latest scan through a supplemental exploited-vulnerability source

That gives you a clean live narrative for:

- KEV ingestion
- source-aware findings
- scan history
- report generation
- scan diffing
- artifact export/import
