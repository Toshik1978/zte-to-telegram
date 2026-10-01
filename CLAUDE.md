# CLAUDE.md

Guidance for Claude Code (and other contributors) working in this repository.

## What this project is

`zte-to-telegram` is a small Python CLI that logs in to a ZTE MC888 5G modem/router, reads
pending SMS messages over its HTTP API, and forwards each one to a Telegram chat via a bot.
It runs one-shot by default (suitable for cron) or continuously with `--loop` (the mode Docker
uses).

## Commands

```bash
uv run zte-to-telegram          # run the CLI (see README.md for flags/env vars)
uv run ruff check .             # lint
uv run ruff format .            # format
uv run pytest --cov             # run tests with coverage
```

Run `uv run ruff format --check .`, `uv run ruff check .`, and `uv run pytest --cov -q` before
committing — CI runs the same checks and updates the README badges from the results.

## Architecture

- `cli.py` — Click-based entry point (`zte-to-telegram` console script, `main()` /
  `cli()`). Loads `.env` via `python-dotenv`, wires flags to env vars via
  `auto_envvar_prefix="ZTE"`, builds the collaborators, and dispatches to one-shot or loop mode.
- `forwarder.py` — `Forwarder`: the orchestration layer. `run_once()` logs in to the modem,
  reads and parses pending SMS, sends each to Telegram, then logs out. `run_loop(interval)`
  calls `run_once()` repeatedly, sleeping `interval` seconds between cycles and swallowing
  per-cycle exceptions so the daemon keeps running.
- `zte/connection.py` — `ZteConnection`: the ZTE MC888 HTTP API client (login/logout,
  password hashing, listing/reading/deleting/marking-read SMS). `zte/exception.py` —
  `ZteModemException` for modem-protocol failures.
- `telegram/client.py` — `TelegramClient`: thin wrapper over the Telegram Bot API
  (`sendMessage`) used to deliver a parsed `Sms`.
- `sms/` — the `Sms` dataclass (`sms/sms.py`) and `parse_sms()` (`sms/parser.py`), which turns
  a raw modem SMS record (GSM-7-encoded content, ZTE's `yy,mm,dd,HH,MM,SS,tz` date format) into
  an `Sms`.

### Flat layout

There is no top-level `zte_to_telegram` package — `cli.py` and `forwarder.py` are top-level
modules, alongside the `zte/`, `sms/`, and `telegram/` packages. Because of this, the wheel
build must list every top-level module/package explicitly in
`[tool.hatch.build.targets.wheel].only-include` in `pyproject.toml`. If you add a new top-level
module or package, add it to `only-include` (and to `[tool.coverage.run].source`) or it will
silently be missing from the built wheel.

## Conventions

- Python 3.14 (see `requires-python` in `pyproject.toml`).
- Private attributes use double-underscore name mangling (e.g. `self.__logger`,
  `self.__connection`) — this is intentional, preserve it rather than switching to a single
  underscore.
- Imports are absolute (`from sms.parser import parse_sms`, not relative imports), even within
  a package.
- The local `telegram/` package is **our own code**, not the `python-telegram-bot` PyPI
  package — it only implements the one Bot API call this project needs
  (`telegram/client.py`). Do not add `python-telegram-bot` as a dependency or assume its API.

## README badges / gist

The CI workflow (`.github/workflows/ci.yml`) publishes live test and coverage badges by writing
`tests.json` and `coverage.json` to a GitHub Gist (id `054d287f6fd9c1cf605957177c7106b2`,
referenced in `README.md` as `GIST_ID`). This requires two repository secrets, created by the
maintainer (not part of any automated setup):

- `GIST_ID` — the gist id above.
- `GIST_SECRET_TOKEN` — a GitHub PAT with `gist` scope, used to update the gist's files.

The badge update step only runs on pushes to `main` (PRs from forks don't have access to the
secrets).

## Git conventions

- Commit directly on `main`.
- Never push without explicit approval.
