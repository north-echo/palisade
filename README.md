# PALISADE

**Practical Audit Library for Industrial Security, Asset Discovery, and Edge Defense**

PALISADE is a pragmatic edge-risk triage layer for small and mid-size utilities, municipal systems, co-ops, and critical infrastructure teams that do not have dedicated OT security staff or budgets for platforms like Dragos, Claroty, or Tenable OT.

The current release does one narrow job: **unauthenticated, non-intrusive edge-device exposure triage**. PALISADE helps identify likely exposed edge appliances, match the evidence it can safely collect against exploited-vulnerability risk, and generate reports that operators, leadership, and auditors can actually use.

It is not another scanner. It is not trying to be a full OT platform. It is a local, operator-friendly way to answer a small set of urgent questions about exposed edge infrastructure.

## Why This Exists

Many critical infrastructure operators sit in an awkward gap:

- they know exposed firewalls, VPN appliances, and gateways are a real risk
- they do not have a mature OT security platform
- they still need to decide what to fix first and how to document that work

PALISADE is built for that gap. It gives under-resourced operators a local, practical way to answer:

- What edge devices are we likely exposing?
- Which ones appear tied to exploited-vulnerability risk?
- What should we prioritize?
- How do we save evidence of that review?

## Why It May Be Useful

PALISADE is designed to be:

- narrower than a commercial OT platform
- more operator-focused than a generic vulnerability scanner
- easier to justify than a large monitoring deployment
- more actionable than a spreadsheet of advisories and CVEs

The point is not comprehensive visibility. The point is fast, defensible prioritization for a class of risks that smaller operators routinely struggle to assess.

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
  - pfSense
  - OPNsense
- Text, JSON, and HTML reports
- Scan history, filtering, and scan diffs
- Scan bundle export/import for offline transfer
- JSON config support
- Fixture-backed demo environment
- Replay-lab validation helpers

## What It Is Not

PALISADE is not:

- another generic scanner with OT branding
- a passive full-network OT monitoring platform
- an authenticated scanner or exploit tool
- a guarantee of exact versioning or exploitability
- a replacement for a proper architecture review or penetration test

The project is intentionally narrow. That is part of the value, not a missing ambition.

## Why This Instead Of Alternatives

If you already have a mature OT security program and platform, PALISADE may not be your main tool.

If you do not, the alternatives are often:

- do nothing until an incident or audit forces action
- hand-run generic scanner templates with weak operational framing
- buy into a much larger platform than the team can realistically adopt

PALISADE is aimed at the space between those outcomes.

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
