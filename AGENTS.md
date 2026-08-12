# Repository Instructions

## Authority and scope

- Read `docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md` and `docs/decisions/0001-gitnexus-development-tooling.md` before an architectural change.
- Treat the approved specification and reviewed source as authoritative. GitNexus output is advisory and cannot override either.
- Keep changes inside the requested stage and avoid modifying unrelated files.

## Development workflow

- Use only the user-local uv-managed CPython 3.12 selected by `uv` for the central project; never silently fall back to system Python 3.13 or 3.13t.
- Confirm the prerequisite with `uv python find --managed-python --system --no-python-downloads 3.12`. This read-only discovery uses `--system` to skip the project `.venv`; `--managed-python` still requires a uv-managed install, `--no-python-downloads` prevents acquisition, and the command does not modify system Python. From Stage 3 onward, normal project execution uses the closed `scripts/invoke-uv.ps1` profiles, which pin absolute tools in the repository `.venv`; do not invoke `uv run` directly. Stop when the managed interpreter is missing; never auto-download an interpreter during ordinary development or verification.
- Treat `uv python install --no-bin --no-registry <exact-version>` as a separately reviewed and approved pre-Stage-1 prerequisite task, never as an ordinary development or verification command.
- Use test-driven development for production behavior: focused failing test, minimum implementation, focused passing test, then broader verification.
- Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1` before claiming completion.
- Report every skipped check, warning, and failure; do not infer success from a partial verification run.
- Ordinary development and verification are offline. After Stage 3 introduces Pydantic, invoke lock resolution/checks, synchronization, installed Python tools, and builds only through closed named profiles in the reviewed repository-controlled `scripts/invoke-uv.ps1` child-process launcher. Every ordinary profile pins the repository/project, ignores ambient uv configuration, requires managed Python 3.12 without downloads, and is explicitly offline; run profiles also disable synchronization and dotenv loading. The launcher requires exactly one resolvable `uv.exe`, invokes its normalized absolute path, and rejects caller-selected Python, scripts, tools, uv flags, and external pytest paths/options. Never dot-source the launcher.
- If a stage's newly approved locked packages are absent locally, stop. First attempt that stage's exact lock and synchronization commands offline. Only an exact, one-time command named in the approved stage plan and separately approved by the user may resolve or acquire the missing packages over the network. Return immediately to the ordinary offline launcher workflow. The historical Stage 1 Task 2 `uv lock` and `uv sync --frozen --no-install-project` exceptions remain bounded to Stage 1; they do not authorize later online commands or unrestricted or permanent network access.

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
- Pydantic dependency code alone may read the fixed, non-secret process variable `PYDANTIC_DISABLE_PLUGINS=__all__`. A repository-controlled launcher must set that exact literal unconditionally in the child environment before Python starts whenever the child may import Pydantic models, construct Pydantic validators, or generate Pydantic schemas; it must not inspect or preserve an alternative ambient value. Before invocation, that launcher may remove only the reviewed fixed literal uv, Python, virtual-environment, pytest, coverage/pytest-cov, and mypy selection/injection variable names required for fail-closed tool selection, by assigning null to each named process entry. It must never enumerate environment entries; call an environment-value getter; or inspect, save, print, log, persist, restore, or branch on any removed value. Application, domain, configuration, schema, and CLI Python modules must not read, set, mutate, branch on, print, log, persist, or expose the Pydantic control. It is deterministic dependency hardening, not application or user configuration, a credential, an experiment input, a canonical field, a runtime product input, or hash material. No other environment-variable exception is authorized.
- Project-scoped Codex MCP configuration may set only the reviewed, non-secret GitNexus control variables explicitly required by ADR 0001. Those variables are developer-tool configuration, not application configuration, credentials, or runtime product inputs. No other exception is implied.
- Do not add Binance, exchange, broker, or network-client integration during Project 1.
