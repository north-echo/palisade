# PALISADE

Practical Audit Library for Industrial Security, Asset Discovery, and Edge Defense.

The project overview and current planning documents live in:

- `PALISADE_README.md`
- `PALISADE_SPEC.md`
- `PALISADE_PHASE1_ISSUES.md`

Current status:

- Installable Python package scaffold
- Working Click CLI with `kev-sync`, `edge-audit`, `report`, `scan-export`, and `scan-import`
- SQLite-backed KEV storage with CISA and supplemental-source support, including VulnCheck adapter support
- Edge-device fingerprinting and KEV matching for SonicWall, Fortinet, F5, Cisco, Palo Alto, Ivanti, and Citrix
- Text, JSON, and HTML reporting with source-aware findings and scan diffs
- Scan bundle export/import for artifact packaging and offline transfer
- Fixture-backed demo environment builder under `tools/build_demo.py`
- Basic test, lint, type-check, and CI configuration

Useful docs:

- [PALISADE_README.md](./PALISADE_README.md)
- [docs/GETTING_STARTED.md](./docs/GETTING_STARTED.md)
- [docs/CONFIG.md](./docs/CONFIG.md)
- [docs/DEMO.md](./docs/DEMO.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
