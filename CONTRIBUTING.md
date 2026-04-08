# Contributing

## Scope

PALISADE is intentionally narrow. Contributions should preserve the project’s core constraints:

- non-intrusive scanning only
- no authenticated collection in Phase 1
- operator-readable output over feature sprawl
- evidence-backed findings over aggressive claims

## Development

```bash
ruff check .
mypy
pytest -q
```

## Sign-Off

All commits should include a sign-off line to satisfy the project’s DCO-style requirement.

Example:

```text
Signed-off-by: Your Name <you@example.com>
```

Use:

```bash
git commit -s
```

## Pull Requests

- Keep changes narrowly scoped.
- Add or update tests when behavior changes.
- Do not add intrusive probe logic without explicit discussion.
- Document assumptions for vendor fingerprinting and version extraction.
