# Getting Started

## Install

```bash
git clone https://github.com/north-echo/palisade.git
cd palisade
pip install -e .
```

If editable install is unavailable in your environment, the source tree also works directly:

```bash
PYTHONPATH=src python3 -m palisade --help
```

## Initialize Config

```bash
PYTHONPATH=src python3 -m palisade config init
PYTHONPATH=src python3 -m palisade config show
```

## Sync KEV Data

```bash
PYTHONPATH=src python3 -m palisade kev-sync
PYTHONPATH=src python3 -m palisade kev-sync --status
```

To add a supplemental source file:

```bash
PYTHONPATH=src python3 -m palisade kev-sync --supplemental-source path/to/source.json --status
```

## Run A Scan

```bash
PYTHONPATH=src python3 -m palisade edge-audit --target 192.0.2.10
PYTHONPATH=src python3 -m palisade edge-audit --target 192.0.2.0/30 --discover
```

## Generate Reports

```bash
PYTHONPATH=src python3 -m palisade report --latest
PYTHONPATH=src python3 -m palisade report --latest --format html --output latest.html
PYTHONPATH=src python3 -m palisade report --latest --previous --format json
```

## Export And Import Scan Bundles

```bash
PYTHONPATH=src python3 -m palisade scan-export --latest
PYTHONPATH=src python3 -m palisade scan-import --input artifacts/<scan-id>.zip
```
