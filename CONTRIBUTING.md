# Contributing

Sweeper is an active security scanner. Changes must preserve its authorization,
scope, evidence, and degraded-coverage guarantees.

## Development setup

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
```

External scanner binaries are optional for unit development. Tests that drive
an installed binary skip when that binary is unavailable.

## Change requirements

- Add a regression test for every bug fix and new stage behavior.
- Keep live targets, credentials, raw responses, and run directories out of the
  repository, fixtures, issues, and pull requests.
- Use synthetic reserved names such as `example.test` in tests and docs.
- Never weaken scope filtering, redirect controls, credential scoping, rate
  limits, time limits, or the `full`-level acknowledgement gate.
- A stage that cannot complete its advertised coverage must report `partial`,
  `failed`, or `skipped`; it must not convert missing work into a clean result.
- New external tools must be identity-checked and argument-probed in preflight.

See `docs/ADDING-A-STAGE.md` for the stage contract and pipeline rules.
