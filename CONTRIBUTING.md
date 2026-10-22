# Contributing

Thanks for helping make NetDoctor better. Bug reports with a JSON report attached
(`netdoctor <target> --json`) are especially valuable, as wrong diagnoses are the most important bugs.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
make check        # ruff + mypy --strict + pytest (coverage gate: 85%)
```

## Principles

1. **Standard library only.** A new runtime dependency needs a strong justification.
2. **Checks never raise on network failure**: they return a result with `ok=False`, a human
   `error` and a stable `error_kind`.
3. **Diagnosis is separate from measurement.** Checks measure; `analysis.py` interprets.
4. **Be honest about uncertainty.** If something has an innocent explanation, say "possibly".
5. **Tests need no internet.** Use the local-server fixtures in `tests/conftest.py`.
6. **Validate untrusted input** at the boundary (`target.py`) and never use a shell.

## Adding a check

1. Add a result dataclass to `models.py` (with `ok`, `error`, `error_kind`).
2. Implement `checks/<name>.py` returning that dataclass; wrap I/O in `try/except Exception`.
3. Wire it into `runner.diagnose` (it runs inside the shared thread pool).
4. Interpret it in `analysis.py`, emitting `Finding`s with a stable `UPPER_SNAKE` code and a hint.
5. Show it in `report.check_lines`, then add tests and document new codes in the README.

## Adding or changing a finding

Add a table-driven case to `tests/test_analysis.py`. Changing a finding **code** or any JSON field is
a breaking change: bump `SCHEMA_VERSION` in `models.py` and note it in the CHANGELOG.

## Commit / PR

Keep PRs focused, update the CHANGELOG, and make sure CI is green on all OS/Python combinations.
