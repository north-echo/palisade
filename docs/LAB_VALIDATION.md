# Lab Validation

PALISADE now includes a lightweight local replay lab for scanner validation.

## Start The Mock Lab

```bash
PYTHONPATH=src python3 tools/run_mock_lab.py
```

This starts local HTTP targets backed by the repository’s stored HTTP fixtures for:

- Cisco
- Citrix
- F5
- Fortinet
- Ivanti
- Palo Alto
- SonicWall

The script prints the listening URLs and an example `edge-audit` command.

## What It Validates

- the real HTTP probe path in `core/device.py`
- vendor matcher behavior against live local responses
- scanner orchestration without monkeypatching

## What It Does Not Validate

- TLS certificate handling
- SSH/banner-only detection
- real appliance timing and protocol quirks

Use it as a controlled smoke-test and demo layer, not as a substitute for appliance testing.

## Run A Validation Pass

```bash
PYTHONPATH=src python3 tools/run_validation.py
```

This writes:

- `validation/out/validation.db`
- `validation/out/validation-summary.md`
- `validation/out/validation-summary.json`

The validation run seeds demo KEV data, starts the replay targets, runs the real scanner against them, and records the matched vendors and generated findings.
