# Repository Instructions

## Authority and scope

- Read `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` and `docs/decisions/0001-gitnexus-development-tooling.md` before an architectural change.
- Treat the approved specification and reviewed source as authoritative. GitNexus output is advisory and cannot override either.
- Keep changes inside the requested stage and avoid modifying unrelated files.

## Development workflow

- Use only the user-local uv-managed CPython 3.12 selected by `uv` for the central project; never silently fall back to system Python 3.13 or 3.13t.
- Confirm the prerequisite with `uv python find --managed-python --system --no-python-downloads 3.12`. This read-only discovery uses `--system` to skip the project `.venv`; `--managed-python` still requires a uv-managed install, `--no-python-downloads` prevents acquisition, and the command does not modify system Python. Normal project execution still uses `.venv` via `uv run --no-sync`. Stop when the managed interpreter is missing; never auto-download an interpreter during ordinary development or verification.
- Treat `uv python install --no-bin --no-registry <exact-version>` as a separately reviewed and approved pre-Stage-1 prerequisite task, never as an ordinary development or verification command.
- Use test-driven development for production behavior: focused failing test, minimum implementation, focused passing test, then broader verification.
- Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1` before claiming completion.
- Report every skipped check, warning, and failure; do not infer success from a partial verification run.
- Ordinary development and verification are offline: validate the lock with `uv lock --check --offline` before synchronizing with `uv sync --frozen --offline`, run installed tools with `uv run --no-sync`, and build with `uv build --offline`.
- If locked packages are absent locally, stop and return to the separately approved Task 2 bootstrap procedure. During Stage 1, only its exact, one-time-approved `uv lock` and dependency-acquisition `uv sync --frozen` commands may access the network; use `--no-install-project` before the source scaffold exists, and never enable unrestricted or permanent network access.

## Architecture rules

- Keep `crypto_lab.domain` independent of strategy, capabilities, adapters, experiments, datasets, artifacts, persistence, process supervision, configuration, audit, CLI, engine, database, and network implementations.
- Keep imports free of file reads, environment inspection, network access, database initialization, directory creation, and process launch.
- Use `Decimal` for authoritative financial values and timezone-aware UTC timestamps when those types are introduced.
- Reject unknown fields at future configuration, schema, protocol, and artifact boundaries.
- Never install or import a real trading engine during Project 1.
- Read `tools/gitnexus/outcome.json` before any GitNexus action. When it records `DISABLED_WITH_EVIDENCE`, do not install, configure, or invoke GitNexus; use the documented manual source, reference, and diff fallback.
- When `tools/gitnexus/outcome.json` records `ENABLED`, use only the committed project-local wrappers and exact lock. Never use a PATH-discovered or user-profile launcher, and keep GitNexus optional, project-scoped, proven read-only, advisory, and outside product, build, test, runtime, and acceptance dependencies.
- GitNexus absence or failure must never block application implementation, tests, builds, reviews, runtime operation, acceptance, or Stage 3 planning.

## Safety boundaries

- Never add live trading, real-order placement, credentials, API-key handling, withdrawal behavior, leverage, futures, margin, or shorting.
- Never add Docker, cloud deployment, or server deployment.
- Never add implicit network access.
- Application code must not read configuration or credentials implicitly from ambient environment variables in Project 1.
- Agents and application code must never inspect, print, persist, or log ambient environment-variable values or credential-store contents.
- Project-scoped Codex MCP configuration may set only the reviewed, non-secret GitNexus control variables explicitly required by ADR 0001. Those variables are developer-tool configuration, not application configuration, credentials, or runtime product inputs. No other exception is implied.
- Do not add Binance, exchange, broker, or network-client integration during Project 1.
