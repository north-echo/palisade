# Configuration

PALISADE supports a JSON config file for common defaults.

Default lookup order:

1. `--config <path>`
2. `PALISADE_CONFIG`
3. `./palisade.json`

## Create A Starter Config

```bash
PYTHONPATH=src python3 -m palisade config init
```

## Supported Fields

```json
{
  "db_path": "data/palisade.db",
  "default_kev_scope": "expanded",
  "default_concurrency": 1,
  "default_artifact_dir": "artifacts",
  "vulncheck_token": ""
}
```

## Notes

- CLI flags still override config values.
- `vulncheck_token` may also be provided via `VULNCHECK_API_TOKEN`.
- `scan-export --latest` writes into `default_artifact_dir` when `--output` is omitted.
