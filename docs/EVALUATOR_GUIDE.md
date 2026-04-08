# Evaluator Guide

This guide is for expert preview reviewers evaluating whether PALISADE is viable, useful, and scoped correctly.

## What To Evaluate

Focus on these questions:

- Is the problem framing real for under-resourced utilities and critical infrastructure operators?
- Is unauthenticated edge-device triage useful enough to justify the tool?
- Are the current findings and reports credible without overclaiming certainty?
- Is the current Phase 1 scope narrow in the right way?
- What would block real operational adoption?

## Recommended Review Path

Use this sequence:

1. Read [README.md](../README.md)
2. Read [docs/LIMITATIONS.md](./LIMITATIONS.md)
3. Review [docs/ARCHITECTURE.md](./ARCHITECTURE.md)
4. Run the demo workflow
5. Review example reports and diff output
6. Run the validation workflow if you want to inspect current fixture-backed coverage

## Fastest Hands-On Path

From the repo root:

```bash
pip install -e .
PYTHONPATH=src python3 tools/build_demo.py
```

Artifacts will be written under `demo/out/`.

Useful files:

- `demo/out/SUMMARY.md`
- `demo/out/reports/latest-report.txt`
- `demo/out/reports/latest-report.html`
- `demo/out/reports/diff-report.txt`
- `demo/out/bundles/*.zip`

## Validation Path

Run:

```bash
PYTHONPATH=src python3 tools/run_validation.py
```

Outputs will be written under `validation/out/`.

Useful files:

- `validation/out/validation-summary.md`
- `validation/out/validation-summary.json`

## What To Pressure-Test

- Fingerprint realism: are the vendor/product/version claims conservative enough?
- Finding quality: are KEV matches useful, or too weak to drive action?
- Report usefulness: would operators or leadership understand the outputs?
- Source handling: is `strict` versus `expanded` KEV scope a good model?
- Product fit: is this genuinely useful for smaller operators?

## Feedback Requested

Please review [docs/FEEDBACK_QUESTIONS.md](./FEEDBACK_QUESTIONS.md) and answer as directly as possible. Short, blunt feedback is more useful than broad encouragement.

## Preview Status

This is a pre-release expert preview build.

Assume:

- the core workflow exists
- the data model and CLI may still change
- field accuracy claims are still being validated
- the best current use is evaluation, not broad production rollout
