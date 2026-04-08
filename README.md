# PALISADE

**Practical Audit Library for Industrial Security, Asset Discovery, and Edge Defense**

PALISADE is an operator-first security toolkit for small and mid-size utilities, municipal systems, co-ops, and critical infrastructure teams that do not have dedicated OT security staff or budget for a commercial platform.

The current release focuses on one narrow job: **unauthenticated, non-intrusive edge-device exposure triage**. PALISADE helps identify likely exposed edge appliances, match the evidence it can safely collect against known exploited vulnerabilities, and generate reports that are usable by operators, leadership, and auditors.

## Why This Exists

Many critical infrastructure operators sit in an awkward gap:

- they know exposed firewalls, VPN appliances, and gateways are a real risk
- they do not have a mature OT security platform
- they still need to decide what to fix first and how to document that work

PALISADE is built for that gap. It is not trying to be a full OT monitoring product. It is trying to give under-resourced operators a local, practical way to answer:

- What edge devices are we likely exposing?
- Which ones appear tied to exploited-vulnerability risk?
- What should we prioritize?
- How do we save evidence of that review?

## What It Does Today

Current implemented capabilities:

- Local SQLite-backed KEV storage
- CISA KEV sync plus supplemental-source support
- Source-aware findings with `strict` and `expanded` KEV scope
- Edge-device fingerprinting and version matching for:
  - SonicWall
  - Fortinet
  - F5
  - Cisco
  - Palo Alto
  - Ivanti
  - Citrix
- Text, JSON, and HTML reports
- Scan history, filtering, and scan diffs
- Scan bundle export/import for offline transfer
- JSON config support
- Fixture-backed demo environment
- Replay-lab validation helpers

## What It Is Not

PALISADE is not:

- a passive full-network OT monitoring platform
- an authenticated scanner or exploit tool
- a guarantee of exact versioning or exploitability
- a replacement for a proper architecture review or penetration test

The project is intentionally narrow. That is part of the value.

## Quick Start

```bash
git clone https://github.com/north-echo/palisade.git
cd palisade
pip install -e .
```

If you are working directly from source:

```bash
PYTHONPATH=src python3 -m palisade --help
```

Example workflow:

```bash
# initialize config
PYTHONPATH=src python3 -m palisade config init

# sync KEV data
PYTHONPATH=src python3 -m palisade kev-sync

# run a scan
PYTHONPATH=src python3 -m palisade edge-audit --target 192.0.2.10

# generate a report
PYTHONPATH=src python3 -m palisade report --latest --format html --output latest.html

# export a bundle
PYTHONPATH=src python3 -m palisade scan-export --latest
```

## Demo And Validation

Build the fixture-backed demo:

```bash
PYTHONPATH=src python3 tools/build_demo.py
```

Run the replay-lab validation pass:

```bash
PYTHONPATH=src python3 tools/run_validation.py
```

## Core Docs

- [Project overview](./PALISADE_README.md)
- [Implementation spec](./PALISADE_SPEC.md)
- [Phase 1 issue list](./PALISADE_PHASE1_ISSUES.md)
- [Getting started](./docs/GETTING_STARTED.md)
- [Evaluator guide](./docs/EVALUATOR_GUIDE.md)
- [Limitations](./docs/LIMITATIONS.md)
- [Architecture overview](./docs/ARCHITECTURE.md)
- [Feedback questions](./docs/FEEDBACK_QUESTIONS.md)
- [Config](./docs/CONFIG.md)
- [Demo runbook](./docs/DEMO.md)
- [Lab validation](./docs/LAB_VALIDATION.md)
- [Release checklist](./docs/RELEASE.md)
- [Security policy](./SECURITY.md)
- [Changelog](./CHANGELOG.md)
- [Contributing](./CONTRIBUTING.md)

## Config Example

See [palisade.example.json](./palisade.example.json) for a starter config file.

## Status

PALISADE is pre-release, but the core Phase 1 edge-audit workflow is implemented and test-covered. The current work is in validation, demoability, and release hardening rather than basic capability scaffolding.
