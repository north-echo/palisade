## Summary

- What this release adds
- Who it is for
- What remains intentionally out of scope

## Highlights

- Supported vendors:
  - SonicWall
  - Fortinet
  - F5
  - Cisco
  - Palo Alto
  - Ivanti
  - Citrix
- KEV source support:
  - CISA KEV
  - supplemental imported sources
  - VulnCheck adapter path
- Reports:
  - text
  - JSON
  - HTML
- Scan portability:
  - export/import bundles

## Validation

- `ruff check .`
- `mypy`
- `pytest -q`
- demo build
- replay-lab validation

## Known Limitations

- best-effort unauthenticated fingerprinting only
- no authenticated collection
- no passive monitoring
- no exploit validation
