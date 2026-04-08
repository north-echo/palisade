# Release Prep

Use this checklist before tagging a release.

## Versioning

1. Update [src/palisade/__init__.py](../src/palisade/__init__.py)
2. Update [setup.py](../setup.py)
3. Add a new entry to [CHANGELOG.md](../CHANGELOG.md)

## Quality Gates

Run:

```bash
ruff check .
mypy
pytest -q
python3 tools/check_release.py
```

If available on a normal development host, also run:

```bash
PYTHONPATH=src python3 tools/build_demo.py
PYTHONPATH=src python3 tools/run_validation.py
```

## Docs

Confirm these are current:

- [README.md](../README.md)
- [PALISADE_README.md](../PALISADE_README.md)
- [SECURITY.md](../SECURITY.md)
- [docs/GETTING_STARTED.md](./GETTING_STARTED.md)
- [docs/CONFIG.md](./CONFIG.md)
- [docs/DEMO.md](./DEMO.md)
- [docs/LAB_VALIDATION.md](./LAB_VALIDATION.md)

## Artifacts

Prepare or verify:

- example config file
- demo output if you want to share screenshots or sample reports
- validation summary if you want to cite fixture-backed validation coverage

## Tagging

Suggested flow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Release Notes

Summarize:

- supported vendors
- KEV source support
- report/export/import capabilities
- known limitations
