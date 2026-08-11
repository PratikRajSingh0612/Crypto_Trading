# Project 1 Guarded GitNexus Development Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Project 1 Stage 2 with a reviewed, machine-readable
GitNexus governance decision while preserving a fully offline application
workflow and permitting Stage 3 planning after either `ENABLED` or
`DISABLED_WITH_EVIDENCE`.

**Architecture:** Put every GitNexus artifact outside the Python package and
make a machine-readable supply-chain manifest plus terminal outcome record the
governance authority. A strict
pre-installation gate must prove the exact package's server-side read-only,
repository, default-repository, token-budget, and tool-surface controls before
any package, MCP configuration, wrapper, or index is created. The official
1.6.9 source inspected on 2026-08-11 does not implement the four mandatory MCP
environment controls, so execution of this plan follows
`DISABLED_WITH_EVIDENCE`; the `ENABLED` branch below is complete but is
unreachable for this pin and may not be used to weaken the gate.

**Tech Stack:** Windows PowerShell; Git; Node.js 25.9.0; project-local pnpm
11.9.0; exact npm package `gitnexus` 1.6.9; JSON; TOML; Python 3.12 standard
library; pytest; the existing independently offline `uv` verification
workflow; Codex project MCP configuration.

## Global Constraints

- Authority order is the approved architecture specification, ADR 0001, the
  master roadmap, repository instructions and verified Stage 1 behavior, this
  plan, then advisory GitNexus output.
- Planning was audited on clean local `main` at
  `56d029e8e6d3c67dc6309b267c74833a09d2e419`. Execution begins from the later
  clean local-main commit that contains this approved plan and has that Stage 1
  commit as an ancestor. Record that exact execution commit as
  `stage2BaseCommit`, use it for the complete review, and make no Stage 2 edit
  in the main checkout.
- Stage 2 records exactly one terminal outcome: `ENABLED` or
  `DISABLED_WITH_EVIDENCE`. Both complete Stage 2 and permit Stage 3 planning.
- For the researched 1.6.9 pin, the required outcome is
  `DISABLED_WITH_EVIDENCE` because the exact tagged MCP implementation lacks
  `GITNEXUS_MCP_READ_ONLY`, `GITNEXUS_MCP_ALLOWED_REPOS`,
  `GITNEXUS_MCP_DEFAULT_REPO`, and
  `GITNEXUS_MCP_DEFAULT_MAX_TOKENS`.
- Do not substitute a prerelease, release candidate, moving tag, global
  launcher, PATH lookup, `pnpm dlx`, Corepack shim, plugin, or generated setup
  for the exact package reviewed here.
- If a later architecture decision selects another package version, revise and
  reapprove this plan with that exact identity before enabling it. Do not
  reinterpret the conditional templates as approval for another pin.
- GitNexus remains optional, advisory, local development tooling. It is never a
  Python dependency, product dependency, runtime dependency, build dependency,
  test oracle, application service, adapter, trading engine, data source, or
  acceptance dependency.
- `[project].dependencies`, Python optional dependency groups, `uv.lock`, the
  package build, and `scripts/verify.ps1` must remain independent of GitNexus.
- Normal development and every verification workflow remain offline. The only
  possible Stage 2 network command is the exact one-time, user-approved,
  pinned package acquisition command in Task 4. The selected 1.6.9 disabled
  route never requests or runs it.
- Do not inspect, print, persist, or log ambient environment-variable values,
  credentials, npm or pnpm authentication material, browser data, credential
  stores, private paths, private keys, API keys, or tokens.
- Project-scoped Codex configuration may set only the four exact non-secret ADR
  MCP control variables. No fifth developer-tool variable is authorized, and
  no application or agent may enumerate the ambient environment to discover
  values.
- No real engine, Binance integration, exchange client, network client, live
  trading, paper trading, wallet, tax, TDS, risk, dashboard, LLM, Docker,
  cloud, or server feature enters Stage 2.
- Do not use setup automation, generated instructions, generated skills,
  hooks, wiki, web UI, serve mode, publishing, repository groups, raw Cypher,
  rename, embeddings, remote models, remote embedding endpoints, or telemetry.
- Use TDD for wrapper and validation behavior. Package manifests, generated
  lockfiles, JSON/TOML configuration, ignore files, and documentation are
  explicit configuration/documentation exceptions.
- Run the unchanged ordinary verifier before and after every outcome. A
  GitNexus check never replaces formatting, lint, typing, tests, coverage,
  build, safety review, code review, or diff review.
- Do not begin Stage 3 during this plan's execution.

---

## Planning research record

Research was performed on 2026-08-11 using only official GitNexus, npm, and
OpenAI sources. No package was downloaded or installed and no GitNexus
launcher was executed.

### Current local facts

| Fact | Verified value | Planning consequence |
|---|---|---|
| Node.js | `v25.9.0` | Satisfies GitNexus 1.6.9's `>=22.0.0` engine floor. |
| npm | `11.9.0` | Not selected: the tagged 1.6.9 guidance documents an npm 11 Arborist/optional-dependency failure mode. |
| pnpm | `11.9.0` | Selected for the conditional project-local route. |
| Corepack | unavailable | Never install or use it as a package manager; only the Task 1 read-only availability probe is permitted. Use the verified pnpm executable directly. |
| Existing GitNexus launchers | three user-profile npm shims observed by filename and metadata | Untrusted, never executed, never opened, never used for the version pin. |
| Stage 1 | clean `main` at `56d029e8e6d3c67dc6309b267c74833a09d2e419` | Stage 2 may be planned; ordinary verification remains complete without Node tooling. |

The user-profile portion of any observed launcher path is redacted from
reports. Only launcher name, type, size, and timestamps may be recorded; the
launcher content and unrelated global packages remain uninspected.

| Launcher | Type | Bytes | Created UTC | Modified UTC | Redacted path |
|---|---:|---:|---|---|---|
| `gitnexus.ps1` | PowerShell shim | 869 | `2026-07-09T13:34:41.4690439Z` | `2026-07-09T13:34:41.4801516Z` | `C:\Users\<redacted>\AppData\Roaming\npm\gitnexus.ps1` |
| `gitnexus.cmd` | Command shim | 341 | `2026-07-09T13:34:41.4703392Z` | `2026-07-09T13:34:41.4855769Z` | `C:\Users\<redacted>\AppData\Roaming\npm\gitnexus.cmd` |
| `gitnexus` | Extensionless shim | 421 | `2026-07-09T13:34:41.4703392Z` | `2026-07-09T13:34:41.4845579Z` | `C:\Users\<redacted>\AppData\Roaming\npm\gitnexus` |

### Exact package identity

This table is the reviewed package integrity record for the selected pin.

| Field | Verified value |
|---|---|
| Package | `gitnexus` |
| Stable version | `1.6.9` |
| Distribution integrity | `sha512-Rq5LXFygx7jjMp/YFsIAcnnzuKvvCsb4rxHFILnu05ZOqk7xNXTUSMRa968EOCbxcKFxnhKYaGXoabOUeGZX6A==` |
| Distribution SHA-1 | `23ba4e53a8a6ad7daa501d6c4a8b4e4d8fba57a0` |
| Binary mapping | `{"gitnexus":"dist/cli/index.js"}` |
| Required Node range | `>=22.0.0` |
| License | `PolyForm-Noncommercial-1.0.0` |
| Repository | `git+https://github.com/abhigyanpatwari/GitNexus.git`, directory `gitnexus` |
| Publication timestamp | `2026-07-04T07:13:01.960Z` |
| Selected package manager | pnpm `11.9.0` |

The package declares a `postinstall` lifecycle script and native dependencies.
The conditional pnpm project therefore permits lifecycle scripts only for
`@ladybugdb/core`, `gitnexus`, and `tree-sitter`. No other dependency may run a
build script.

### Commands and primary sources used during planning

These read-only metadata commands were executed during plan authoring:

```powershell
npm view gitnexus version --json
npm view gitnexus@1.6.9 version dist.integrity dist.shasum dist.tarball engines license bin repository scripts dependencies optionalDependencies time --json
npm view gitnexus dist-tags --json
```

Official source identifiers recorded in the supply-chain manifest are:

- `https://www.npmjs.com/package/gitnexus/v/1.6.9`
- `https://registry.npmjs.org/gitnexus/1.6.9`
- `https://github.com/abhigyanpatwari/GitNexus/tree/v1.6.9/gitnexus`
- `https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/package.json`
- `https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/src/cli/analyze-config.ts`
- `https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/src/mcp/server.ts`
- `https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/src/mcp/tools.ts`
- `https://developers.openai.com/codex/mcp`
- `https://developers.openai.com/codex/config-reference`
- `https://developers.openai.com/codex/config-schema.json`

The tagged 1.6.9 `.gitnexusrc` parser accepts a nested `analyze` object,
rejects malformed values and unknown keys, and verifies the keys used in the
conditional file below: `defaultBranch`, `name`, `indexOnly`, `skipAgentsMd`,
`skipSkills`, and `embeddings`. Tagged documentation identifies an additional
environment variable as its extension load-only control, but repository
instructions authorize only the four ADR MCP variables. Therefore that fifth
variable is not placed in any wrapper or Codex configuration; 1.6.9 cannot
satisfy the offline-extension gate without a separately approved ADR revision.

### Decisive control-gap finding

Exact tagged-source review found no implementation reference to any of the
four mandatory MCP variables. The 1.6.9 server registers the complete
GitNexus tool collection; the OpenAI `enabled_tools` field can hide tools from
the Codex client but cannot prove server-side read-only behavior, repository
confinement, a default repository, or a token ceiling. OpenAI's
`default_tools_approval_mode = "writes"` is an approval policy, not a
read-only transformation. Therefore client filtering and approval prompts
cannot satisfy ADR 0001, and Stage 2 must end disabled for this pin.

This is a governance incompatibility, not an application defect. It does not
block application source, tests, builds, reviews, acceptance, or Stage 3
planning.

## Outcome-aware file map

The exact `DISABLED_WITH_EVIDENCE` route for 1.6.9 creates or modifies only:

```text
Create  tools/gitnexus/README.md
Create  tools/gitnexus/supply-chain.json
Create  tools/gitnexus/outcome.json
Create  tests/safety/test_gitnexus_development_tooling.py
Modify  .gitignore
Modify  AGENTS.md
Modify  README.md
Modify  docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md
```

The three files below `tools/gitnexus/` are inert evidence/documentation, not a
Node project or partial installation. The disabled route must not create a
package manifest, pnpm lock, wrapper, installer, MCP configuration, GitNexus
configuration, GitNexus ignore file, local index, or `node_modules`. The
existing Hatch sdist include list excludes `/tools`, so these developer-tool
records do not enter the Python distribution.

The conditional `ENABLED` route would additionally create or modify exactly:

```text
Create  .gitnexusrc
Create  .gitnexusignore
Create  .codex/config.toml
Create  tools/gitnexus/package.json
Create  tools/gitnexus/pnpm-workspace.yaml
Create  tools/gitnexus/pnpm-lock.yaml       # generated; never hand-edited
Create  tools/gitnexus/scripts/gitnexus.ps1
Create  tools/gitnexus/scripts/gitnexus-mcp.ps1
Create  tools/gitnexus/scripts/install.ps1
Create  tools/gitnexus/scripts/verify.ps1
```

Those conditional files are forbidden for the selected 1.6.9 execution. They
exist in this plan so reviewers can evaluate the complete `ENABLED` contract,
not so a worker can bypass Task 1.

## Outcome state machine

1. Task 1 records environment, package, license, integrity, source, and control
   evidence without executing GitNexus.
2. The SDD ledger uses an execution-only route value. It is
   `DISABLED_WITH_EVIDENCE` after any mandatory-gate failure, or
   `ENABLED_CANDIDATE` only after every pre-install gate passes. The candidate
   value is never written to `tools/gitnexus/outcome.json` and is not a
   terminal Stage 2 outcome.
3. The disabled route writes terminal `DISABLED_WITH_EVIDENCE` evidence in
   Task 2. Only `ENABLED_CANDIDATE` may enter the conditional package,
   configuration, wrapper, frozen-lock acquisition, indexing, and MCP tasks.
   It writes terminal `ENABLED` only after all Task 7 acceptance gates pass.
4. Any enabled-path failure immediately disables MCP, removes every partial
   project-local install/config/index, records inspected evidence, and changes
   the final outcome to `DISABLED_WITH_EVIDENCE`.
5. Task 7 proves the selected outcome, ordinary optionality, documentation,
   direct-merge readiness, and clean state.

## Task 1: Stage 2 preflight, environment, existing-launcher, and supply-chain audit

**Files:**
- Create: none
- Modify: none
- Test: none

**Interfaces:**
- Consumes: clean local `main`, the approved Stage 1 commit, installed Node and
  package-manager commands, filename-only launcher metadata, and the research
  record above
- Produces: an execution-route value named `stage2Route`, exact value
  `DISABLED_WITH_EVIDENCE` for 1.6.9, plus redacted preflight evidence consumed
  by Tasks 2-7. A separately revised plan whose complete pre-install gate passes
  uses the non-terminal route `ENABLED_CANDIDATE` until Task 7.

Task 1 ledger entries remain in the active workflow transcript only. Do not
create repository-local `.superpowers/sdd/` scratch until Task 2 adds its exact
ignore rule.

- [ ] **Step 1: Verify main before creating the execution worktree**

Run from the main checkout:

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
git merge-base --is-ancestor 56d029e8e6d3c67dc6309b267c74833a09d2e419 HEAD
```

Expected: all commands exit `0`; status is empty, branch is `main`, HEAD is the
approved plan-bearing local-main commit, and the Stage 1 ancestry check exits
`0`. Record `(git rev-parse HEAD).Trim()` as `stage2BaseCommit`. Stop without
creating a worktree if status/branch/ancestry differs or this plan is absent
from that commit.

- [ ] **Step 2: Create the isolated execution worktree**

Use `superpowers:using-git-worktrees` at execution time to create branch
`project-1-stage-2-gitnexus-tooling` from local `main` in an external sibling
worktree. Do not fetch, pull, push, or contact a remote.

From the worktree, run:

```powershell
$worktreeHead = (git rev-parse HEAD).Trim()
$mainHead = (git rev-parse main).Trim()
$worktreeBase = (git merge-base HEAD main).Trim()
if (
    $worktreeHead -ne $mainHead -or
    $worktreeBase -ne $worktreeHead
) {
    throw "Stage 2 worktree does not begin at the approved local main"
}
git status --short
git branch --show-current
```

Expected: exit `0`, empty status, the exact branch name, and all three commit
values equal `stage2BaseCommit`; the recorded Stage 1 commit remains an
ancestor.

- [ ] **Step 3: Re-run the ordinary verifier before tooling work**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Expected: exit `0`; lock validation, sync, format, lint, mypy, pytest, build,
and Git whitespace all pass offline. GitNexus, Node, MCP, and any index are not
used.

- [ ] **Step 4: Record local Node and package-manager facts without installation**

```powershell
node --version
npm --version
pnpm --version
corepack --version
where.exe node
where.exe npm
where.exe pnpm
Get-Command node,npm,pnpm -All -ErrorAction SilentlyContinue |
    Select-Object CommandType, Name, Source, Path, Version |
    Format-List
```

Expected: Node reports `v25.9.0`, npm and pnpm each report `11.9.0`, Corepack
is unavailable, and every successful command's exit is recorded. A version
drift is recorded and reviewed; it never authorizes an install or package
manager replacement. If Node no longer satisfies `>=22.0.0` or pnpm is absent,
lock `DISABLED_WITH_EVIDENCE`. Satisfying the declared Node range is only a
syntactic prerequisite; it does not prove LadybugDB, tree-sitter, ONNX, or
another native dependency works on this Windows/Node tuple. Native
compatibility remains unproven until the conditional Task 4 doctor and smoke
gates pass.

- [ ] **Step 5: Inspect existing launcher filenames and metadata only**

```powershell
$gitNexusCommands = @(
    Get-Command gitnexus -All -ErrorAction SilentlyContinue
)
where.exe gitnexus
foreach ($command in $gitNexusCommands) {
    $item = Get-Item -LiteralPath $command.Source -Force
    [pscustomobject]@{
        Name = $item.Name
        Extension = $item.Extension
        Length = $item.Length
        CreationTimeUtc = $item.CreationTimeUtc
        LastWriteTimeUtc = $item.LastWriteTimeUtc
        Path = $item.FullName -replace '^C:\\Users\\[^\\]+', 'C:\\Users\\<redacted>'
    }
}
```

Expected: command exit codes and redacted metadata are recorded. Do not invoke,
open, hash, modify, remove, or trust a discovered launcher. Do not inspect any
unrelated global package tree.

- [ ] **Step 6: Review the exact supply-chain and source evidence**

Compare the research table with the three recorded `npm view` outputs and the
tagged official files listed above. Confirm package, version, integrity,
shasum, binary mapping, Node range, license, repository, publication time,
package-manager choice, lifecycle scripts, `.gitnexusrc` keys, and extension
load-only mode. Review the exact dependency and runtime source for Scarf,
update checks, telemetry, remote models, extension acquisition, and other
implicit egress. Do not repeat a network query during implementation.

Expected: the identity is internally consistent. An identity, integrity,
repository, or license mismatch locks `DISABLED_WITH_EVIDENCE`. Independently
review PolyForm Noncommercial 1.0.0 against the project's current personal,
noncommercial use. Any commercial, consulting, distribution, monetization,
unclear, or changed use locks disabled pending a new legal/license review. Any
unavoidable or unproven telemetry, update, extension-download, or runtime
network behavior also locks disabled.

- [ ] **Step 7: Apply the mandatory MCP capability gate**

Record these exact facts in the SDD ledger:

```text
GITNEXUS_MCP_READ_ONLY: absent from tagged 1.6.9 implementation
GITNEXUS_MCP_ALLOWED_REPOS: absent from tagged 1.6.9 implementation
GITNEXUS_MCP_DEFAULT_REPO: absent from tagged 1.6.9 implementation
GITNEXUS_MCP_DEFAULT_MAX_TOKENS: absent from tagged 1.6.9 implementation
server-side seven-tool restriction: not proven for tagged 1.6.9
offline extension behavior without a fifth environment variable: not proven
native Windows/Node dependency compatibility: not proven without installation
stage2Route: DISABLED_WITH_EVIDENCE
```

Expected: the outcome is locked before any package or project-scoped GitNexus
file is created. Do not proceed into an enabled step and do not ask for package
installation approval.

**Focused verification:** Review the exact environment exits, redacted
launcher metadata, official package identity, tagged source, and all five
mandatory control decisions.

**Broader verification:** The unchanged ordinary verifier exits `0` with
GitNexus absent/disabled.

**Security review:** Confirm no launcher ran, no package downloaded, no
environment values were enumerated, no credentials were read, and no remote
operation occurred during implementation.

**Commit:** No commit is permitted. Task 1 is read-only; do not create an empty
audit commit.

**Independent review gate:** A reviewer must independently confirm the exact
1.6.9 tagged source lacks all four variables and that client-side Codex tool
filtering cannot replace server-side controls. A contrary finding stops the
plan for reconciliation; it does not automatically enable the tool.

## Task 2: Pinned project-local package manifest and static configuration using TDD

**Files for the selected disabled route:**
- Create: `tests/safety/test_gitnexus_development_tooling.py`
- Create: `tools/gitnexus/supply-chain.json`
- Create: `tools/gitnexus/outcome.json`
- Modify: `.gitignore`

**Conditional ENABLED-only files:**
- Create: `tools/gitnexus/package.json`
- Create: `tools/gitnexus/pnpm-workspace.yaml`
- Create: `.gitnexusrc`
- Create: `.gitnexusignore`

**Interfaces:**
- Consumes: locked `stage2Route`, exact package and package-manager identity,
  repository root fixture, and existing Stage 1 safety rules
- Produces: a non-sensitive machine-readable outcome and supply-chain record;
  static tests that run without GitNexus; and, only behind a passing enabled
  gate, exact project-local configuration consumed by Tasks 3-6

- [ ] **Step 1: Write the outcome-first static safety test**

Create `tests/safety/test_gitnexus_development_tooling.py` with exactly:

```python
"""Prove GitNexus remains optional, isolated, and outcome-gated."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any, cast

_EXPECTED_GITNEXUS_IGNORE_ENTRIES = {
    "/.git/",
    "/.gitnexus/",
    "/.superpowers/",
    "/.codex/",
    "/.venv/",
    "/venv/",
    "/.uv/",
    "/.uv-cache/",
    "/node_modules/",
    "/tools/gitnexus/node_modules/",
    "/.npm/",
    "/.pnpm-store/",
    "/runtime/",
    "/data/",
    "/artifacts/",
    "/logs/",
    "/runtimes/",
    "/dist/",
    "/build/",
    "/reports/generated/",
    "/generated-reports/",
    "/market-data/",
    "/market_data/",
    "/htmlcov/",
    "__pycache__/",
    "*.py[cod]",
    ".coverage",
    ".coverage.*",
    "/coverage.xml",
    ".ruff_cache/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".hypothesis/",
    "*.egg-info/",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "/secrets/",
    "/credentials/",
    "/.ssh/",
    "/.aws/",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.crt",
    "*.cer",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.duckdb",
    "/paper-wallet/",
    "/paper_wallet/",
    "/tax-records/",
    "/tax_records/",
}
_CANDIDATE_BASE_PATHS = (
    ".gitnexusrc",
    ".gitnexusignore",
    "tools/gitnexus/package.json",
    "tools/gitnexus/pnpm-workspace.yaml",
)
_LATER_ENABLED_PATHS = (
    ".codex/config.toml",
    "tools/gitnexus/pnpm-lock.yaml",
    "tools/gitnexus/scripts/gitnexus.ps1",
    "tools/gitnexus/scripts/gitnexus-mcp.ps1",
    "tools/gitnexus/scripts/install.ps1",
    "tools/gitnexus/scripts/verify.ps1",
)
_ENABLED_ONLY_PATHS = _CANDIDATE_BASE_PATHS + _LATER_ENABLED_PATHS
_GENERATED_ENABLED_PATHS = (
    ".gitnexus",
    "tools/gitnexus/node_modules",
)
_CURRENT_PIN_DISABLED_REASONS = (
    "PINNED_RELEASE_MISSING_REQUIRED_MCP_CONTROLS",
    "PINNED_RELEASE_REQUIRES_UNAUTHORIZED_EXTENSION_CONTROL",
    "NATIVE_RUNTIME_COMPATIBILITY_NOT_PROVEN",
)
_LATE_DISABLED_REASONS = {
    "NODE_REQUIREMENT_NOT_MET",
    "PACKAGE_MANAGER_UNAVAILABLE",
    "PACKAGE_IDENTITY_UNVERIFIED",
    "PACKAGE_INTEGRITY_UNVERIFIED",
    "LICENSE_INCOMPATIBLE_OR_UNCLEAR",
    "OFFLINE_LOCK_GENERATION_FAILED",
    "INSTALLATION_DECLINED",
    "INSTALLATION_FAILED",
    "NATIVE_DEPENDENCY_INCOMPATIBLE",
    "PROJECT_LOCAL_WRAPPER_UNPROVEN",
    "READ_ONLY_MODE_UNPROVEN",
    "TOOL_ALLOWLIST_UNPROVEN",
    "SOURCE_RUNTIME_EXCLUSIONS_UNPROVEN",
    "OFFLINE_EXTENSION_BEHAVIOR_UNPROVEN",
    "CODEX_MCP_UNSTABLE_OR_UNSAFE",
}


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _manifest(repository_root: Path) -> dict[str, Any]:
    return _load_json(repository_root / "tools/gitnexus/supply-chain.json")


def _tracked_paths(repository_root: Path) -> set[str]:
    git_executable = shutil.which("git")
    assert git_executable is not None
    completed = subprocess.run(  # noqa: S603 -- fixed local Git inspection.
        [
            git_executable,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    return {path for path in completed.stdout.split("\0") if path}


def _terminal_outcome(repository_root: Path) -> dict[str, Any] | None:
    path = repository_root / "tools/gitnexus/outcome.json"
    return _load_json(path) if path.exists() else None


def _execution_route(repository_root: Path) -> str:
    outcome = _terminal_outcome(repository_root)
    if outcome is not None:
        value = cast(str, outcome["outcome"])
        assert value in {"ENABLED", "DISABLED_WITH_EVIDENCE"}
        return value

    present = [
        (repository_root / relative_path).exists()
        for relative_path in _CANDIDATE_BASE_PATHS
    ]
    assert all(present), "partial or missing ENABLED_CANDIDATE base files"
    return "ENABLED_CANDIDATE"


def _matches_reviewed_ignore(entries: set[str], relative_path: str) -> bool:
    candidate = relative_path.replace("\\", "/").strip("/")
    candidate_path = PurePosixPath(candidate)
    for entry in entries:
        pattern = entry.strip()
        if pattern.startswith("/"):
            anchored = pattern[1:].rstrip("/")
            if candidate == anchored or candidate.startswith(f"{anchored}/"):
                return True
            continue

        unanchored = pattern.rstrip("/")
        if "/" not in unanchored and any(
            fnmatchcase(part, unanchored) for part in candidate.split("/")
        ):
            return True
        if candidate_path.match(unanchored) or candidate_path.match(f"**/{unanchored}"):
            return True
    return False


def test_supply_chain_identity_is_exact(repository_root: Path) -> None:
    assert _manifest(repository_root) == {
        "schema_version": 1,
        "research_date": "2026-08-11",
        "verification_date": "2026-08-11",
        "package_name": "gitnexus",
        "package_version": "1.6.9",
        "dist_integrity": (
            "sha512-Rq5LXFygx7jjMp/YFsIAcnnzuKvvCsb4rxHFILnu05ZOqk7xNXTUSMRa"
            "968EOCbxcKFxnhKYaGXoabOUeGZX6A=="
        ),
        "dist_shasum": "23ba4e53a8a6ad7daa501d6c4a8b4e4d8fba57a0",
        "license": "PolyForm-Noncommercial-1.0.0",
        "repository_url": "git+https://github.com/abhigyanpatwari/GitNexus.git",
        "repository_tag": "v1.6.9",
        "repository_directory": "gitnexus",
        "published_at_utc": "2026-07-04T07:13:01.960Z",
        "required_node_range": ">=22.0.0",
        "selected_package_manager": "pnpm",
        "selected_package_manager_version": "11.9.0",
        "package_binary_mapping": {"gitnexus": "dist/cli/index.js"},
        "official_sources": [
            "https://registry.npmjs.org/gitnexus/1.6.9",
            (
                "https://github.com/abhigyanpatwari/GitNexus/blob/"
                "v1.6.9/gitnexus/package.json"
            ),
            (
                "https://github.com/abhigyanpatwari/GitNexus/blob/"
                "v1.6.9/gitnexus/src/cli/analyze-config.ts"
            ),
            (
                "https://github.com/abhigyanpatwari/GitNexus/blob/"
                "v1.6.9/gitnexus/src/mcp/server.ts"
            ),
            (
                "https://github.com/abhigyanpatwari/GitNexus/blob/"
                "v1.6.9/gitnexus/src/mcp/tools.ts"
            ),
            "https://developers.openai.com/codex/mcp",
            "https://developers.openai.com/codex/config-reference",
        ],
    }


def test_execution_route_is_candidate_or_terminal(repository_root: Path) -> None:
    route = _execution_route(repository_root)
    assert route in {
        "ENABLED_CANDIDATE",
        "ENABLED",
        "DISABLED_WITH_EVIDENCE",
    }
    outcome = _terminal_outcome(repository_root)
    if route == "ENABLED_CANDIDATE":
        assert outcome is None
    else:
        assert outcome is not None
        assert outcome["outcome"] == route


def test_gitnexus_is_absent_from_python_dependencies(repository_root: Path) -> None:
    pyproject = _load_toml(repository_root / "pyproject.toml")
    project = cast(dict[str, Any], pyproject["project"])
    serialized = json.dumps(pyproject, sort_keys=True).lower()

    assert project["dependencies"] == []
    assert "optional-dependencies" not in project
    assert "gitnexus" not in serialized
    assert (
        "gitnexus"
        not in (repository_root / "uv.lock").read_text(encoding="utf-8").lower()
    )


def test_ordinary_verifier_never_invokes_gitnexus(repository_root: Path) -> None:
    verifier = (repository_root / "scripts/verify.ps1").read_text(encoding="utf-8")

    for forbidden_executable in ("gitnexus", "node", "npm", "pnpm", "corepack"):
        assert (
            re.search(
                rf"(?i)(?<![a-z0-9_-]){forbidden_executable}(?![a-z0-9_-])",
                verifier,
            )
            is None
        )


def test_repository_local_sdd_ledger_is_ignored(repository_root: Path) -> None:
    gitignore = (repository_root / ".gitignore").read_text(encoding="utf-8")
    entries = set(gitignore.splitlines())

    assert "/.superpowers/sdd/" in entries
    assert "/tools/gitnexus/node_modules/" in entries


def test_disabled_outcome_has_no_partial_tooling(repository_root: Path) -> None:
    if _execution_route(repository_root) != "DISABLED_WITH_EVIDENCE":
        return

    outcome = _terminal_outcome(repository_root)
    assert outcome is not None
    assert outcome["stage_3_planning_permitted"] is True
    reason_codes = cast(list[str], outcome["reason_codes"])
    assert reason_codes
    control_values = cast(dict[str, bool], outcome["required_mcp_controls"])
    assert set(control_values) == {
        "GITNEXUS_MCP_READ_ONLY",
        "GITNEXUS_MCP_ALLOWED_REPOS",
        "GITNEXUS_MCP_DEFAULT_REPO",
        "GITNEXUS_MCP_DEFAULT_MAX_TOKENS",
        "server_side_seven_tool_allowlist",
    }
    if tuple(reason_codes) == _CURRENT_PIN_DISABLED_REASONS:
        assert all(value is False for value in control_values.values())
    else:
        assert len(reason_codes) == 1
        assert reason_codes[0] in _LATE_DISABLED_REASONS
        assert all(isinstance(value, bool) for value in control_values.values())
    assert outcome["project_state"] == {
        "codex_mcp_configured": False,
        "index_present": False,
        "package_installed": False,
        "partial_configuration_present": False,
    }
    for relative_path in _ENABLED_ONLY_PATHS:
        assert not (repository_root / relative_path).exists(), relative_path
    for relative_path in _GENERATED_ENABLED_PATHS:
        assert not (repository_root / relative_path).exists(), relative_path


def test_candidate_package_and_static_configuration_are_exact(
    repository_root: Path,
) -> None:
    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
        for relative_path in _CANDIDATE_BASE_PATHS:
            assert not (repository_root / relative_path).exists()
        return

    package = _load_json(repository_root / "tools/gitnexus/package.json")
    assert package["private"] is True
    assert package["packageManager"] == "pnpm@11.9.0"
    assert package["dependencies"] == {"gitnexus": "1.6.9"}
    workspace = (repository_root / "tools/gitnexus/pnpm-workspace.yaml").read_text(
        encoding="utf-8"
    )
    assert workspace == (
        "strictDepBuilds: true\n"
        "allowBuilds:\n"
        "  '@ladybugdb/core': true\n"
        "  gitnexus: true\n"
        "  tree-sitter: true\n"
    )
    assert "dangerouslyAllowAllBuilds" not in workspace

    rc = _load_json(repository_root / ".gitnexusrc")
    assert rc == {
        "analyze": {
            "defaultBranch": "main",
            "embeddings": False,
            "indexOnly": True,
            "name": "crypto-trading-lab",
            "skipAgentsMd": True,
            "skipSkills": True,
        }
    }
    ignore_entries = {
        line.strip()
        for line in (repository_root / ".gitnexusignore")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert ignore_entries == _EXPECTED_GITNEXUS_IGNORE_ENTRIES
    ignored_probes = (
        ".git/config",
        ".gitnexus/graph.db",
        ".superpowers/sdd/state.json",
        ".codex/scratch.txt",
        ".venv/pyvenv.cfg",
        "tools/gitnexus/node_modules/package/index.js",
        "runtime/paper-wallet.json",
        "data/market.sqlite",
        "artifacts/report.json",
        "logs/run.log",
        "runtimes/python.exe",
        "reports/generated/tax.csv",
        "market-data/candles.parquet",
        "src/pkg/__pycache__/module.pyc",
        "src/pkg/example.egg-info/PKG-INFO",
        "nested/.hypothesis/examples/data",
        "nested/.mypy_cache/state.json",
        "nested/.pytest_cache/v/cache/nodeids",
        "nested/.ruff_cache/content",
        "coverage.xml",
        "nested/.env.local",
        "secrets/api.json",
        "credentials/exchange.json",
        ".ssh/id_ed25519",
        "certificate.pem",
        "paper-wallet/state.db",
        "tax-records/2026.sqlite",
    )
    assert all(
        _matches_reviewed_ignore(ignore_entries, probe) for probe in ignored_probes
    )
    visible_probes = (
        "src/crypto_lab/artifacts/__init__.py",
        "tests/unit/test_cli.py",
        "scripts/verify.ps1",
        "docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md",
        "docs/decisions/0001-gitnexus-development-tooling.md",
        "docs/development/verification.md",
        "AGENTS.md",
        "README.md",
        "pyproject.toml",
    )
    assert all(
        not _matches_reviewed_ignore(ignore_entries, probe) for probe in visible_probes
    )


def test_node_package_files_are_isolated(repository_root: Path) -> None:
    tracked_manifests = {
        path
        for path in _tracked_paths(repository_root)
        if PurePosixPath(path).name
        in {"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"}
    }
    expected: set[str] = set()
    if _execution_route(repository_root) != "DISABLED_WITH_EVIDENCE":
        expected = {
            "tools/gitnexus/package.json",
            "tools/gitnexus/pnpm-workspace.yaml",
        }
        if (repository_root / "tools/gitnexus/pnpm-lock.yaml").exists():
            expected.add("tools/gitnexus/pnpm-lock.yaml")
    assert tracked_manifests == expected


def test_manifest_and_config_contain_no_secret_fields(repository_root: Path) -> None:
    manifest = _manifest(repository_root)
    outcome = _terminal_outcome(repository_root)
    texts = [json.dumps(manifest, sort_keys=True)]
    if outcome is not None:
        texts.append(json.dumps(outcome, sort_keys=True))
    for relative_path in _ENABLED_ONLY_PATHS:
        path = repository_root / relative_path
        if path.exists():
            texts.append(path.read_text(encoding="utf-8"))
    combined = "\n".join(texts)

    for forbidden_field in (
        "api_key",
        "apikey",
        "password",
        "credential",
        "auth_token",
        "access_token",
    ):
        assert (
            re.search(
                rf"(?im)^\s*[\"']?{forbidden_field}[\"']?\s*[:=]",
                combined,
            )
            is None
        )
    assert re.search(r"[a-z]:\\users\\[^<]", combined, re.IGNORECASE) is None
```

- [ ] **Step 2: Run the new test and confirm red**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
```

Expected: exit `1` because the supply-chain and outcome manifests do not
exist. No GitNexus executable or Node package is required.

- [ ] **Step 3: Ignore and create the exact restart-safe SDD ledger**

Apply this exact `.gitignore` patch:

```diff
 # Generated Project 1 and future runtime state
 /runtime/
 /data/
 /artifacts/
 /logs/
 /runtimes/
 /.gitnexus/
+/.superpowers/sdd/
+/tools/gitnexus/node_modules/
```

Then run:

```powershell
$null = git check-ignore --no-index -- .superpowers/sdd/stage-2-probe
if ($LASTEXITCODE -ne 0) {
    throw "Repository-local SDD scratch is not ignored"
}

$stage2BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage2BaseCommit)) {
    throw "Unable to determine the Stage 2 base commit"
}
$stage2Route = "DISABLED_WITH_EVIDENCE"
$ledgerRoot = ".superpowers/sdd/stage-2-gitnexus"
$ledgerPath = Join-Path -Path $ledgerRoot -ChildPath "state.json"
New-Item -ItemType Directory -Path $ledgerRoot -Force | Out-Null
$ledger = [ordered]@{
    schema_version = 1
    branch = "project-1-stage-2-gitnexus-tooling"
    base_commit = $stage2BaseCommit
    route = $stage2Route
    terminal_outcome = $null
    completed_tasks = @(1)
    resume_task = 2
    resume_step = 4
    pre_restart_commit = $null
    repository_status = "DIRTY_EXPECTED"
}
$ledgerJson = $ledger | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
$null = git check-ignore --no-index -- $ledgerPath
if ($LASTEXITCODE -ne 0) {
    throw "The Stage 2 SDD ledger is not ignored"
}
```

Expected: exit `0`. The exact ignored ledger is
`.superpowers/sdd/stage-2-gitnexus/state.json`; it contains no absolute path,
username, environment value, credential, or tool output. This rule ignores
only local SDD scratch, not the complete `.superpowers/` tree. For 1.6.9 the
route line above is immutable. A separately revised, approved pin may replace
only that line with `$stage2Route = "ENABLED_CANDIDATE"` after Task 1 proves
every mandatory gate; that value remains ledger-only and never appears in
terminal `outcome.json`.

- [ ] **Step 4: Create the exact supply-chain record and route-specific outcome**

Create `tools/gitnexus/supply-chain.json` with exactly:

```json
{
  "schema_version": 1,
  "research_date": "2026-08-11",
  "verification_date": "2026-08-11",
  "package_name": "gitnexus",
  "package_version": "1.6.9",
  "dist_integrity": "sha512-Rq5LXFygx7jjMp/YFsIAcnnzuKvvCsb4rxHFILnu05ZOqk7xNXTUSMRa968EOCbxcKFxnhKYaGXoabOUeGZX6A==",
  "dist_shasum": "23ba4e53a8a6ad7daa501d6c4a8b4e4d8fba57a0",
  "license": "PolyForm-Noncommercial-1.0.0",
  "repository_url": "git+https://github.com/abhigyanpatwari/GitNexus.git",
  "repository_tag": "v1.6.9",
  "repository_directory": "gitnexus",
  "published_at_utc": "2026-07-04T07:13:01.960Z",
  "required_node_range": ">=22.0.0",
  "selected_package_manager": "pnpm",
  "selected_package_manager_version": "11.9.0",
  "package_binary_mapping": {
    "gitnexus": "dist/cli/index.js"
  },
  "official_sources": [
    "https://registry.npmjs.org/gitnexus/1.6.9",
    "https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/package.json",
    "https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/src/cli/analyze-config.ts",
    "https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/src/mcp/server.ts",
    "https://github.com/abhigyanpatwari/GitNexus/blob/v1.6.9/gitnexus/src/mcp/tools.ts",
    "https://developers.openai.com/codex/mcp",
    "https://developers.openai.com/codex/config-reference"
  ]
}
```

For the selected 1.6.9 route, create `tools/gitnexus/outcome.json` with
exactly:

```json
{
  "schema_version": 1,
  "stage": "project-1-stage-2",
  "outcome": "DISABLED_WITH_EVIDENCE",
  "stage_3_planning_permitted": true,
  "decision_date": "2026-08-11",
  "package_name": "gitnexus",
  "package_version": "1.6.9",
  "reason_codes": [
    "PINNED_RELEASE_MISSING_REQUIRED_MCP_CONTROLS",
    "PINNED_RELEASE_REQUIRES_UNAUTHORIZED_EXTENSION_CONTROL",
    "NATIVE_RUNTIME_COMPATIBILITY_NOT_PROVEN"
  ],
  "required_mcp_controls": {
    "GITNEXUS_MCP_READ_ONLY": false,
    "GITNEXUS_MCP_ALLOWED_REPOS": false,
    "GITNEXUS_MCP_DEFAULT_REPO": false,
    "GITNEXUS_MCP_DEFAULT_MAX_TOKENS": false,
    "server_side_seven_tool_allowlist": false
  },
  "project_state": {
    "package_installed": false,
    "codex_mcp_configured": false,
    "index_present": false,
    "partial_configuration_present": false
  },
  "fallback": [
    "review_normative_sources",
    "search_source_and_references_with_rg",
    "inspect_base_to_head_diff",
    "run_ordinary_offline_verification"
  ]
}
```

The manifests record no username, absolute local path, credential, token,
authentication setting, or environment-variable value discovered from the
machine. The `false` control values mean "not implemented/proven by the exact
package," not "configured false." On `ENABLED_CANDIDATE`, create the identical
supply-chain record but do not create `outcome.json`; the ledger is the sole
location for the intermediate route, and Task 7 creates the terminal outcome.

- [ ] **Step 5: Run the selected disabled static test and confirm green**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
uv run --no-sync pytest -o addopts="" tests/safety -q
```

Expected: both commands exit `0` with no outcome-based skip. On the disabled
route, every conditional test positively asserts that its package, config,
wrapper, lock, or index path is absent, and the Python dependency boundary is
unchanged.

- [ ] **Step 6: Apply the conditional ENABLED static files only after a passing gate**

For completeness, the exact candidate files are specified below. Because Task
1 locked `DISABLED_WITH_EVIDENCE` for 1.6.9, record this step as
`NOT_RUN_CONTROL_GATE_FAILED` in the SDD ledger and create none of them.

Conditional `tools/gitnexus/package.json`:

```json
{
  "name": "crypto-trading-lab-gitnexus-tooling",
  "version": "0.0.0",
  "private": true,
  "description": "Optional project-scoped GitNexus development tooling.",
  "license": "UNLICENSED",
  "packageManager": "pnpm@11.9.0",
  "engines": {
    "node": ">=22.0.0"
  },
  "dependencies": {
    "gitnexus": "1.6.9"
  }
}
```

Conditional `tools/gitnexus/pnpm-workspace.yaml`:

```yaml
strictDepBuilds: true
allowBuilds:
  '@ladybugdb/core': true
  gitnexus: true
  tree-sitter: true
```

Conditional `.gitnexusrc`:

```json
{
  "analyze": {
    "defaultBranch": "main",
    "name": "crypto-trading-lab",
    "indexOnly": true,
    "skipAgentsMd": true,
    "skipSkills": true,
    "embeddings": false
  }
}
```

Conditional `.gitnexusignore`:

```gitignore
# Version control and developer-agent scratch
/.git/
/.gitnexus/
/.superpowers/
/.codex/

# Python environments, caches, and build output
/.venv/
/venv/
/.uv/
/.uv-cache/
__pycache__/
*.py[cod]
.pytest_cache/
.hypothesis/
.coverage
.coverage.*
/coverage.xml
/htmlcov/
.ruff_cache/
.mypy_cache/
/dist/
/build/
*.egg-info/

# Node tooling and package-manager caches
/node_modules/
/tools/gitnexus/node_modules/
/.npm/
/.pnpm-store/

# Generated runtime, data, artifacts, and reports
/runtime/
/data/
/artifacts/
/logs/
/runtimes/
/reports/generated/
/generated-reports/
/market-data/
/market_data/

# Environment, credentials, certificates, and private keys
.env
.env.*
**/.env
**/.env.*
/secrets/
/credentials/
/.ssh/
/.aws/
*.pem
*.key
*.p12
*.pfx
*.crt
*.cer

# Local databases and paper/tax state
*.sqlite
*.sqlite3
*.db
*.duckdb
/paper-wallet/
/paper_wallet/
/tax-records/
/tax_records/
```

This file intentionally does not exclude `src/`, `tests/`, `scripts/`,
`docs/superpowers/specs/`, `docs/decisions/`, `docs/development/`, `AGENTS.md`,
`README.md`, or `pyproject.toml`.

No route-specific `.gitignore` patch follows. Both outcomes retain the exact
project-local `node_modules` rule above so an aborted or later retried
installation cannot expose generated packages. Do not add a broad
`node_modules/` rule. pnpm continues to use its existing user-level content
store; Stage 2 creates no repository-local pnpm store. The existing
`/.gitnexus/` rule remains.

- [ ] **Step 7: Run focused and broader verification**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
uv run --no-sync ruff check tests/safety/test_gitnexus_development_tooling.py
uv run --no-sync mypy tests/safety/test_gitnexus_development_tooling.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
git status --short
```

Expected for the selected route: all commands exit `0`; the ordinary verifier
uses no GitNexus; status contains only `.gitignore`, the test, and two JSON
evidence files.

**Focused verification:** The test is red before the manifest and green only
after the exact outcome record exists.

**Broader verification:** The complete ordinary verifier remains offline and
passes without GitNexus, Node tooling, MCP, or an index.

**Security review:** Inspect the two files in full. Confirm no secret field,
local absolute path, username, package executable, or install behavior exists.

**Commit:**

For `DISABLED_WITH_EVIDENCE`, use:

```powershell
git add .gitignore tests/safety/test_gitnexus_development_tooling.py tools/gitnexus/supply-chain.json tools/gitnexus/outcome.json
git diff --cached --check
git diff --cached
git commit -m "test: record guarded gitnexus outcome"
```

Expected: one commit containing exactly the four named files.

For a separately approved `ENABLED_CANDIDATE`, commit every Task 2 candidate
file before Task 3; do not leave configuration dirty across a task boundary:

```powershell
git add .gitignore .gitnexusrc .gitnexusignore tests/safety/test_gitnexus_development_tooling.py tools/gitnexus/supply-chain.json tools/gitnexus/package.json tools/gitnexus/pnpm-workspace.yaml
git diff --cached --check
git diff --cached
git commit -m "test: establish guarded gitnexus candidate"
git status --short
```

Expected: commit succeeds with exactly the seven named paths and status is
clean. `outcome.json`, the lock, wrappers, install, index, and MCP config remain
absent.

- [ ] **Step 8: Persist the Task 2 checkpoint in the ignored ledger**

After the route-specific commit, run:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.completed_tasks = @(1, 2)
$ledger.resume_task = 3
$ledger.resume_step = 1
$ledger.repository_status = "CLEAN"
$ledgerJson = $ledger | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
git status --short
```

Expected: status is empty because the ledger is ignored. Re-read the JSON and
confirm `base_commit`, `branch`, and `route` are unchanged.

**Independent review gate:** A reviewer must verify the test does not need
GitNexus installed, the manifest matches official metadata, the false controls
match tagged source, and no enabled-only path exists.

## Task 3: Safety tests, wrappers, and approval-gated installer using TDD

**Files for the selected disabled route:**
- Create: none
- Modify: none
- Test: `tests/safety/test_gitnexus_development_tooling.py`

**Conditional ENABLED-only files:**
- Create: `tools/gitnexus/scripts/gitnexus.ps1`
- Create: `tools/gitnexus/scripts/gitnexus-mcp.ps1`
- Create: `tools/gitnexus/scripts/install.ps1`
- Create: `tools/gitnexus/scripts/verify.ps1`
- Modify: `tests/safety/test_gitnexus_development_tooling.py` through the exact
  conditional red-green patch below

**Interfaces:**
- Consumes: an `ENABLED_CANDIDATE` gate, the project-local pnpm manifest, exact
  local launcher path, fixed repository registry name, and existing Python
  safety test
- Produces conditionally: one allowlisted CLI wrapper, one fixed MCP wrapper,
  one explicit package-acquisition gate, and one independently offline optional
  tooling verifier

- [ ] **Step 1: Prove the disabled route rejects every executable artifact**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_disabled_outcome_has_no_partial_tooling -q
```

Expected for 1.6.9: exit `0`; every enabled-only package, lock, wrapper,
configuration, install, and index path is absent. Record all conditional steps
below as `NOT_RUN_CONTROL_GATE_FAILED`.

- [ ] **Step 2: On `ENABLED_CANDIDATE`, add behavioral wrapper tests and run red**

This step is prohibited for 1.6.9. On a separately revised and approved exact
pin whose ignored ledger says `ENABLED_CANDIDATE`, apply this exact patch to
the Task 2 test:

```diff
@@
     assert re.search(r"[a-z]:\\users\\[^<]", combined, re.IGNORECASE) is None
+
+
+def _run_powershell(
+    script: Path,
+    *arguments: str,
+    cwd: Path,
+) -> subprocess.CompletedProcess[str]:
+    powershell = shutil.which("powershell.exe")
+    assert powershell is not None
+    return subprocess.run(  # noqa: S603 - fixed system executable and argument array
+        [
+            powershell,
+            "-NoLogo",
+            "-NoProfile",
+            "-NonInteractive",
+            "-ExecutionPolicy",
+            "Bypass",
+            "-File",
+            str(script),
+            *arguments,
+        ],
+        cwd=cwd,
+        check=False,
+        capture_output=True,
+        shell=False,
+        text=True,
+        timeout=10,
+    )
+
+
+def _run_powershell_command(
+    command: str,
+    *,
+    cwd: Path,
+) -> subprocess.CompletedProcess[str]:
+    powershell = shutil.which("powershell.exe")
+    assert powershell is not None
+    return subprocess.run(  # noqa: S603 - fixed system executable and argument array
+        [
+            powershell,
+            "-NoLogo",
+            "-NoProfile",
+            "-NonInteractive",
+            "-ExecutionPolicy",
+            "Bypass",
+            "-Command",
+            command,
+        ],
+        cwd=cwd,
+        check=False,
+        capture_output=True,
+        shell=False,
+        text=True,
+        timeout=10,
+    )
+
+
+def _copy_tooling_script(
+    repository_root: Path,
+    tmp_path: Path,
+    sandbox_name: str,
+    script_name: str,
+) -> tuple[Path, Path]:
+    sandbox = tmp_path / sandbox_name
+    scripts = sandbox / "tools/gitnexus/scripts"
+    scripts.mkdir(parents=True)
+    script = scripts / script_name
+    script.write_bytes(
+        (repository_root / "tools/gitnexus/scripts" / script_name).read_bytes()
+    )
+    return sandbox, script
+
+
+def _copy_wrapper_with_fake_launcher(
+    repository_root: Path,
+    tmp_path: Path,
+    sandbox_name: str,
+    wrapper_name: str,
+    launcher_body: str,
+) -> tuple[Path, Path]:
+    sandbox = tmp_path / sandbox_name
+    scripts = sandbox / "tools/gitnexus/scripts"
+    launcher = sandbox / "tools/gitnexus/node_modules/.bin/gitnexus.cmd"
+    scripts.mkdir(parents=True)
+    launcher.parent.mkdir(parents=True)
+    wrapper = scripts / wrapper_name
+    wrapper.write_bytes(
+        (repository_root / "tools/gitnexus/scripts" / wrapper_name).read_bytes()
+    )
+    launcher.write_text(launcher_body, encoding="utf-8", newline="")
+    return sandbox, wrapper
+
+
+def _recording_launcher(exit_code: int = 0) -> str:
+    return (
+        "@echo off\r\n"
+        '> "%CD%\\fake-invocation.txt" type nul\r\n'
+        ":record\r\n"
+        'if "%~1"=="" goto done\r\n'
+        '>> "%CD%\\fake-invocation.txt" echo %~1\r\n'
+        "shift\r\n"
+        "goto record\r\n"
+        ":done\r\n"
+        f"exit /b {exit_code}\r\n"
+    )
+
+
+def test_candidate_cli_wrapper_has_exact_command_profiles(
+    repository_root: Path, tmp_path: Path
+) -> None:
+    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
+        assert not (repository_root / "tools/gitnexus/scripts/gitnexus.ps1").exists()
+        return
+
+    profiles = {
+        "version": ["-V"],
+        "doctor": ["doctor"],
+        "status": ["status"],
+        "query": [
+            "query",
+            "version-only command",
+            "--repo",
+            "crypto-trading-lab",
+            "--limit",
+            "5",
+        ],
+        "context": [
+            "context",
+            "main",
+            "--repo",
+            "crypto-trading-lab",
+            "--file",
+            "src/crypto_lab/cli/main.py",
+            "--limit",
+            "10",
+        ],
+        "impact": [
+            "impact",
+            "main",
+            "--direction",
+            "upstream",
+            "--repo",
+            "crypto-trading-lab",
+            "--file",
+            "src/crypto_lab/cli/main.py",
+            "--depth",
+            "3",
+            "--limit",
+            "25",
+        ],
+        "trace": [
+            "trace",
+            "test_main_without_arguments_prints_help_and_succeeds",
+            "main",
+            "--from-file",
+            "tests/unit/test_cli.py",
+            "--to-file",
+            "src/crypto_lab/cli/main.py",
+            "--include-tests",
+            "--repo",
+            "crypto-trading-lab",
+            "--depth",
+            "10",
+        ],
+        "detect-changes": [
+            "detect-changes",
+            "--scope",
+            "compare",
+            "--base-ref",
+            "main",
+            "--repo",
+            "crypto-trading-lab",
+            "--limit",
+            "25",
+        ],
+        "check": ["check", "--json", "--repo", "crypto-trading-lab"],
+    }
+    for command, expected in profiles.items():
+        sandbox, wrapper = _copy_wrapper_with_fake_launcher(
+            repository_root,
+            tmp_path,
+            command,
+            "gitnexus.ps1",
+            _recording_launcher(),
+        )
+        result = _run_powershell(wrapper, command, cwd=tmp_path)
+        assert result.returncode == 0, result.stderr
+        assert (sandbox / "fake-invocation.txt").read_text(
+            encoding="utf-8"
+        ).splitlines() == expected
+
+    sandbox, wrapper = _copy_wrapper_with_fake_launcher(
+        repository_root,
+        tmp_path,
+        "analyze",
+        "gitnexus.ps1",
+        _recording_launcher(),
+    )
+    result = _run_powershell(wrapper, "analyze", cwd=tmp_path)
+    assert result.returncode == 0, result.stderr
+    assert (sandbox / "fake-invocation.txt").read_text(
+        encoding="utf-8"
+    ).splitlines() == [
+        "analyze",
+        str(sandbox),
+        "--index-only",
+        "--name",
+        "crypto-trading-lab",
+        "--drop-embeddings",
+    ]
+
+
+def test_candidate_cli_wrapper_rejects_extra_arguments_and_propagates_exit(
+    repository_root: Path, tmp_path: Path
+) -> None:
+    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
+        return
+
+    sandbox, wrapper = _copy_wrapper_with_fake_launcher(
+        repository_root,
+        tmp_path,
+        "reject",
+        "gitnexus.ps1",
+        _recording_launcher(),
+    )
+    rejected = _run_powershell(wrapper, "query", "--repo", "other", cwd=tmp_path)
+    assert rejected.returncode != 0
+    assert not (sandbox / "fake-invocation.txt").exists()
+
+    sandbox, wrapper = _copy_wrapper_with_fake_launcher(
+        repository_root,
+        tmp_path,
+        "exit",
+        "gitnexus.ps1",
+        _recording_launcher(17),
+    )
+    propagated = _run_powershell(wrapper, "version", cwd=tmp_path)
+    assert propagated.returncode == 17
+
+
+def test_candidate_wrappers_fail_without_local_launcher_and_mcp_is_exact(
+    repository_root: Path, tmp_path: Path
+) -> None:
+    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
+        for name in ("gitnexus.ps1", "gitnexus-mcp.ps1"):
+            assert not (repository_root / "tools/gitnexus/scripts" / name).exists()
+        return
+
+    missing_root = tmp_path / "missing"
+    missing_script = missing_root / "tools/gitnexus/scripts/gitnexus.ps1"
+    missing_script.parent.mkdir(parents=True)
+    missing_script.write_bytes(
+        (repository_root / missing_script.relative_to(missing_root)).read_bytes()
+    )
+    missing = _run_powershell(missing_script, "version", cwd=tmp_path)
+    assert missing.returncode != 0
+    assert "project-local pinned GitNexus installation is absent" in missing.stderr
+
+    launcher_body = (
+        "@echo off\r\n"
+        "(\r\n"
+        "echo %~1\r\n"
+        "echo READ_ONLY=%GITNEXUS_MCP_READ_ONLY%\r\n"
+        "echo ALLOWED=%GITNEXUS_MCP_ALLOWED_REPOS%\r\n"
+        "echo DEFAULT=%GITNEXUS_MCP_DEFAULT_REPO%\r\n"
+        "echo TOKENS=%GITNEXUS_MCP_DEFAULT_MAX_TOKENS%\r\n"
+        ') > "%CD%\\fake-invocation.txt"\r\n'
+        "exit /b 0\r\n"
+    )
+    sandbox, wrapper = _copy_wrapper_with_fake_launcher(
+        repository_root,
+        tmp_path,
+        "mcp",
+        "gitnexus-mcp.ps1",
+        launcher_body,
+    )
+    result = _run_powershell(wrapper, cwd=tmp_path)
+    assert result.returncode == 0, result.stderr
+    assert (sandbox / "fake-invocation.txt").read_text(
+        encoding="utf-8"
+    ).splitlines() == [
+        "mcp",
+        "READ_ONLY=1",
+        "ALLOWED=crypto-trading-lab",
+        "DEFAULT=crypto-trading-lab",
+        "TOKENS=8000",
+    ]
+    mcp_source = (
+        repository_root / "tools/gitnexus/scripts/gitnexus-mcp.ps1"
+    ).read_text(encoding="utf-8")
+    assignments = set(re.findall(r"\$env:(GITNEXUS_[A-Z0-9_]+)\s*=", mcp_source))
+    assert assignments == {
+        "GITNEXUS_MCP_ALLOWED_REPOS",
+        "GITNEXUS_MCP_DEFAULT_MAX_TOKENS",
+        "GITNEXUS_MCP_DEFAULT_REPO",
+        "GITNEXUS_MCP_READ_ONLY",
+    }
+    assert "GITNEXUS_LBUG_EXTENSION_INSTALL" not in mcp_source
+
+
+def test_candidate_install_script_fails_closed_before_package_manager(
+    repository_root: Path, tmp_path: Path
+) -> None:
+    install_path = repository_root / "tools/gitnexus/scripts/install.ps1"
+    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
+        assert not install_path.exists()
+        return
+
+    sandbox, install_script = _copy_tooling_script(
+        repository_root,
+        tmp_path,
+        "install-no-approval",
+        "install.ps1",
+    )
+    no_approval = _run_powershell(install_script, cwd=sandbox)
+    assert no_approval.returncode == 2
+    assert (
+        "Approval required for: pnpm.cmd --dir .\\tools\\gitnexus install "
+        "--frozen-lockfile --ignore-scripts"
+    ) in no_approval.stderr
+    assert not (sandbox / "tools/gitnexus/node_modules").exists()
+
+    sandbox, install_script = _copy_tooling_script(
+        repository_root,
+        tmp_path,
+        "install-invalid-pin",
+        "install.ps1",
+    )
+    package_path = sandbox / "tools/gitnexus/package.json"
+    package_path.write_text(
+        json.dumps(
+            {
+                "packageManager": "pnpm@11.9.0",
+                "dependencies": {"gitnexus": "0.0.0"},
+            }
+        ),
+        encoding="utf-8",
+    )
+    invalid_pin = _run_powershell(
+        install_script,
+        "-ApprovedExactAcquisition",
+        cwd=sandbox,
+    )
+    assert invalid_pin.returncode != 0
+    assert "exact reviewed pin" in invalid_pin.stderr
+    assert not (sandbox / "tools/gitnexus/node_modules").exists()
+
+
+def test_candidate_tooling_verifier_stops_after_first_failure(
+    repository_root: Path, tmp_path: Path
+) -> None:
+    verifier_path = repository_root / "tools/gitnexus/scripts/verify.ps1"
+    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
+        assert not verifier_path.exists()
+        return
+
+    sandbox, verifier = _copy_tooling_script(
+        repository_root,
+        tmp_path,
+        "verify-first-failure",
+        "verify.ps1",
+    )
+    marker = sandbox / "calls.txt"
+    quoted_marker = str(marker).replace("'", "''")
+    quoted_verifier = str(verifier).replace("'", "''")
+    command = (
+        f"$marker = '{quoted_marker}'; "
+        "function global:pnpm.cmd { Add-Content -LiteralPath $marker pnpm; "
+        "throw 'planned package-manager failure' }; "
+        "function global:uv { Add-Content -LiteralPath $marker uv }; "
+        "function global:powershell.exe { "
+        "Add-Content -LiteralPath $marker powershell }; "
+        f"& '{quoted_verifier}'"
+    )
+    completed = _run_powershell_command(command, cwd=sandbox)
+    assert completed.returncode == 1
+    assert marker.read_text(encoding="utf-8").splitlines() == ["pnpm"]
+    assert "planned package-manager failure" in completed.stderr
+
+
+def test_candidate_script_sources_enforce_exact_safe_command_surface(
+    repository_root: Path,
+) -> None:
+    script_root = repository_root / "tools/gitnexus/scripts"
+    names = (
+        "gitnexus.ps1",
+        "gitnexus-mcp.ps1",
+        "install.ps1",
+        "verify.ps1",
+    )
+    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
+        assert all(not (script_root / name).exists() for name in names)
+        return
+
+    sources = {name: (script_root / name).read_text(encoding="utf-8") for name in names}
+    combined = "\n".join(sources.values())
+    for forbidden_executable in ("npx", "pnpx", "corepack"):
+        assert (
+            re.search(
+                rf"(?i)(?<![a-z0-9_-]){forbidden_executable}(?![a-z0-9_-])",
+                combined,
+            )
+            is None
+        )
+    assert re.search(r"(?i)npm(?:\.cmd)?\s+install\s+-g", combined) is None
+    assert re.search(r"(?i)pnpm(?:\.cmd)?\s+dlx", combined) is None
+
+    cli_source = sources["gitnexus.ps1"].lower()
+    for forbidden_profile in (
+        '"setup"',
+        '"hook"',
+        '"hooks"',
+        '"skill"',
+        '"skills"',
+        '"wiki"',
+        '"serve"',
+        '"publish"',
+        '"cypher"',
+        '"group"',
+        '"groups"',
+        '"rename"',
+        '"embeddings"',
+    ):
+        assert forbidden_profile not in cli_source
+    assert '"--drop-embeddings"' in cli_source
+
+    install_source = sources["install.ps1"]
+    exact_acquisition = (
+        "pnpm.cmd --dir .\\tools\\gitnexus install --frozen-lockfile --ignore-scripts"
+    )
+    assert install_source.count(exact_acquisition) == 1
+    assert f"& {exact_acquisition}" not in install_source
+    assert 'ValidateSet("Preflight", "Postflight")' in install_source
+    assert "--offline" not in install_source
+    verifier_source = sources["verify.ps1"]
+    for required_literal in (
+        '"--frozen-lockfile"',
+        '"--offline"',
+        '"--ignore-scripts"',
+        '"tests/safety/test_gitnexus_development_tooling.py"',
+        '"gitnexus.ps1"',
+    ):
+        assert required_literal in verifier_source
```

Then run:

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
```

Expected before script creation: exit `1` because all four reviewed script
paths are absent. The tests execute only a temporary fake `.cmd` launcher,
fail-closed acquisition fixtures, and a first-failure verifier harness through
reviewed argument-array subprocess calls; they neither install nor invoke
GitNexus or a package manager.

- [ ] **Step 3: Create the exact conditional CLI wrapper**

Conditional `tools/gitnexus/scripts/gitnexus.ps1`:

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet(
        "version",
        "doctor",
        "analyze",
        "status",
        "query",
        "context",
        "impact",
        "trace",
        "detect-changes",
        "check"
    )]
    [string]$Command
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (
    Resolve-Path -LiteralPath (
        Join-Path -Path $PSScriptRoot -ChildPath "..\..\.."
    )
).Path
$localLauncher = Join-Path -Path $repositoryRoot -ChildPath (
    "tools\gitnexus\node_modules\.bin\gitnexus.cmd"
)

if (-not (Test-Path -LiteralPath $localLauncher -PathType Leaf)) {
    throw "The project-local pinned GitNexus installation is absent"
}
if ($args.Count -ne 0) {
    throw "Pass-through arguments are prohibited; select one reviewed command profile"
}

$nativeArguments = switch ($Command) {
    "version" { @("-V") }
    "doctor" { @("doctor") }
    "analyze" {
        @(
            "analyze",
            $repositoryRoot,
            "--index-only",
            "--name",
            "crypto-trading-lab",
            "--drop-embeddings"
        )
    }
    "status" { @("status") }
    "query" {
        @(
            "query",
            "version-only command",
            "--repo",
            "crypto-trading-lab",
            "--limit",
            "5"
        )
    }
    "context" {
        @(
            "context",
            "main",
            "--repo",
            "crypto-trading-lab",
            "--file",
            "src/crypto_lab/cli/main.py",
            "--limit",
            "10"
        )
    }
    "impact" {
        @(
            "impact",
            "main",
            "--direction",
            "upstream",
            "--repo",
            "crypto-trading-lab",
            "--file",
            "src/crypto_lab/cli/main.py",
            "--depth",
            "3",
            "--limit",
            "25"
        )
    }
    "trace" {
        @(
            "trace",
            "test_main_without_arguments_prints_help_and_succeeds",
            "main",
            "--from-file",
            "tests/unit/test_cli.py",
            "--to-file",
            "src/crypto_lab/cli/main.py",
            "--include-tests",
            "--repo",
            "crypto-trading-lab",
            "--depth",
            "10"
        )
    }
    "detect-changes" {
        @(
            "detect-changes",
            "--scope",
            "compare",
            "--base-ref",
            "main",
            "--repo",
            "crypto-trading-lab",
            "--limit",
            "25"
        )
    }
    "check" { @("check", "--json", "--repo", "crypto-trading-lab") }
    default { throw "Unreachable unapproved command" }
}

Push-Location -LiteralPath $repositoryRoot
try {
    & $localLauncher @nativeArguments
    $nativeExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

exit $nativeExitCode
```

The `ValidateSet` is the complete CLI surface. Every profile has an exact
argument array, repository-scoped commands hard-code `crypto-trading-lab`, and
analysis hard-codes index-only mode and embedding deletion. `list` is omitted
because 1.6.9 cannot constrain it to one registry; `clean` is omitted because
rollback removes the already-validated worktree-local index directly. No PDG
mode or pass-through argument is representable, and there is no PATH fallback.

- [ ] **Step 4: Create the exact conditional MCP wrapper**

Conditional `tools/gitnexus/scripts/gitnexus-mcp.ps1`:

```powershell
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repositoryRoot = (
    Resolve-Path -LiteralPath (
        Join-Path -Path $PSScriptRoot -ChildPath "..\..\.."
    )
).Path
$localLauncher = Join-Path -Path $repositoryRoot -ChildPath (
    "tools\gitnexus\node_modules\.bin\gitnexus.cmd"
)

if (-not (Test-Path -LiteralPath $localLauncher -PathType Leaf)) {
    throw "The project-local pinned GitNexus installation is absent"
}

$env:GITNEXUS_MCP_READ_ONLY = "1"
$env:GITNEXUS_MCP_ALLOWED_REPOS = "crypto-trading-lab"
$env:GITNEXUS_MCP_DEFAULT_REPO = "crypto-trading-lab"
$env:GITNEXUS_MCP_DEFAULT_MAX_TOKENS = "8000"

Push-Location -LiteralPath $repositoryRoot
try {
    & $localLauncher "mcp"
    $nativeExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

exit $nativeExitCode
```

This exact wrapper may exist only after tagged package source proves all four
variables are implemented as fail-closed controls. Setting an ignored variable
does not satisfy the proof. The same source review must prove graph extensions
cannot install or contact a network during MCP startup without any fifth
environment variable. If native offline/load-only behavior is absent or
unclear, `ENABLED_CANDIDATE` fails; do not add the unsupported fifth variable.

- [ ] **Step 5: Create the exact conditional acquisition script**

Conditional `tools/gitnexus/scripts/install.ps1`:

```powershell
[CmdletBinding()]
param(
    [switch]$ApprovedExactAcquisition,

    [ValidateSet("Preflight", "Postflight")]
    [string]$Phase = "Preflight"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (
    Resolve-Path -LiteralPath (
        Join-Path -Path $PSScriptRoot -ChildPath "..\..\.."
    )
).Path
$toolingRoot = Join-Path -Path $repositoryRoot -ChildPath "tools\gitnexus"
$packagePath = Join-Path -Path $toolingRoot -ChildPath "package.json"
$workspacePath = Join-Path -Path $toolingRoot -ChildPath "pnpm-workspace.yaml"
$lockPath = Join-Path -Path $toolingRoot -ChildPath "pnpm-lock.yaml"
$localLauncher = Join-Path -Path $toolingRoot -ChildPath (
    "node_modules\.bin\gitnexus.cmd"
)

if (-not $ApprovedExactAcquisition) {
    [Console]::Error.WriteLine(
        "Approval required for: pnpm.cmd --dir .\tools\gitnexus install --frozen-lockfile --ignore-scripts"
    )
    exit 2
}
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
    throw "The reviewed project-local package manifest is absent"
}

$package = Get-Content -LiteralPath $packagePath -Raw | ConvertFrom-Json
if ($package.dependencies.gitnexus -ne "1.6.9") {
    throw "The package manifest does not contain the exact reviewed pin"
}
if ($package.packageManager -ne "pnpm@11.9.0") {
    throw "The package-manager pin is not pnpm 11.9.0"
}
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw "The independently reviewed frozen lock is absent"
}
$expectedWorkspace = @'
strictDepBuilds: true
allowBuilds:
  '@ladybugdb/core': true
  gitnexus: true
  tree-sitter: true
'@
$workspace = (Get-Content -LiteralPath $workspacePath -Raw).Replace("`r`n", "`n")
if ($workspace -ne ($expectedWorkspace.Replace("`r`n", "`n") + "`n")) {
    throw "The pnpm lifecycle allowlist is not exact"
}

$pnpmVersion = (& pnpm.cmd --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pnpmVersion -ne "11.9.0") {
    throw "The selected pnpm 11.9.0 executable is unavailable"
}
if ($Phase -eq "Postflight" -and
    -not (Test-Path -LiteralPath $localLauncher -PathType Leaf)) {
    throw "The project-local GitNexus launcher was not installed"
}

exit 0
```

The switch records that the exact frozen package-manager command has been
approved; it is not a persistent network permission. This script validates the
exact pin, pnpm version, reviewed lock, lifecycle allowlist, and postflight
launcher but deliberately never executes a package-manager install. Task 4
runs the approved package-manager command itself, byte-for-byte. The
`--ignore-scripts` flag prevents every lifecycle script. If the tool cannot
operate without lifecycle/native initialization, the candidate fails closed
rather than rerunning with scripts.

- [ ] **Step 6: Create the exact conditional tooling verifier**

Conditional `tools/gitnexus/scripts/verify.ps1`:

```powershell
[CmdletBinding()]
param(
    [switch]$RequireIndex
)

$ErrorActionPreference = "Stop"
$verificationExitCode = 0
$repositoryRoot = (
    Resolve-Path -LiteralPath (
        Join-Path -Path $PSScriptRoot -ChildPath "..\..\.."
    )
).Path
$toolingRoot = Join-Path -Path $repositoryRoot -ChildPath "tools\gitnexus"
$cliWrapper = Join-Path -Path $PSScriptRoot -ChildPath "gitnexus.ps1"

function Invoke-ToolingStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    & $Executable @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        $script:verificationExitCode = $LASTEXITCODE
        throw "Tooling command failed with exit code $LASTEXITCODE"
    }
}

Push-Location -LiteralPath $repositoryRoot
try {
    Invoke-ToolingStep "pnpm.cmd" @(
        "--dir",
        $toolingRoot,
        "install",
        "--frozen-lockfile",
        "--offline",
        "--ignore-scripts"
    )
    Invoke-ToolingStep "uv" @(
        "run",
        "--no-sync",
        "pytest",
        "-o",
        "addopts=",
        "tests/safety/test_gitnexus_development_tooling.py",
        "-q"
    )
    Invoke-ToolingStep "powershell.exe" @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $cliWrapper,
        "version"
    )
    Invoke-ToolingStep "powershell.exe" @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $cliWrapper,
        "doctor"
    )
    if ($RequireIndex) {
        Invoke-ToolingStep "powershell.exe" @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $cliWrapper,
            "status"
        )
        Invoke-ToolingStep "powershell.exe" @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $cliWrapper,
            "query"
        )
    }
}
catch {
    if ($verificationExitCode -eq 0) {
        $verificationExitCode = 1
    }
    [Console]::Error.WriteLine($_.Exception.Message)
}
finally {
    Pop-Location
}

exit $verificationExitCode
```

This verifier may synchronize only from the local pnpm store with a frozen
lock and disabled lifecycle scripts. It is optional tooling validation and is never called by
`scripts/verify.ps1`.

- [ ] **Step 7: Run conditional red-green and broader checks**

On `ENABLED_CANDIDATE` only:

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
uv run --no-sync ruff check tests/safety/test_gitnexus_development_tooling.py
uv run --no-sync mypy tests/safety/test_gitnexus_development_tooling.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
```

Expected: all commands exit `0`; CLI/MCP wrapper behavior, acquisition
fail-closed validation, verifier first-failure behavior, and exact safe-source
assertions turn green, while no GitNexus process or package-manager acquisition
runs until Task 4. For 1.6.9, do not run this block.

**Focused verification:** Disabled route proves all wrapper paths remain
absent. Conditional enabled route makes all four script tests red before any
script exists, adds only the exact implementations, then turns behavioral and
source-surface assertions green.

**Broader verification:** The complete ordinary verifier passes independently
and offline.

**Security review:** Review every invocation operator and argument array.
Confirm the wrappers resolve only their sibling project-local launcher, never
construct a shell string, never install implicitly, never enumerate the
ambient environment, and reject every unapproved command family. Confirm the
test suite deterministically forbids npx, pnpx, Corepack, global npm install,
pnpm dlx, setup, hooks, skills, wiki, serve, publish, raw Cypher, groups,
rename, and an embeddings command profile.

**Commit:** The selected disabled route creates no Task 3 change and no commit.
Do not create an empty commit. On an independently reapproved, gate-complete
enabled route, use exactly:

```powershell
git add tools/gitnexus/scripts/gitnexus.ps1 tools/gitnexus/scripts/gitnexus-mcp.ps1 tools/gitnexus/scripts/install.ps1 tools/gitnexus/scripts/verify.ps1 tests/safety/test_gitnexus_development_tooling.py
git diff --cached --check
git diff --cached
git commit -m "chore: add guarded gitnexus wrappers"
```

Then persist the clean checkpoint:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.completed_tasks = @(1, 2, 3)
$ledger.resume_task = 4
$ledger.resume_step = 1
$ledger.repository_status = "CLEAN"
$ledgerJson = $ledger | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
git status --short
```

Expected: the wrapper/test commit is independently reviewable and status is
empty; the ignored ledger records the exact next step.

**Independent review gate:** Review the disabled absence proof for 1.6.9. A
conditional enabled review must separately trace every native command and
confirm that validation, error handling, root resolution, native exit
propagation, and offline extension behavior are exact.

## Task 4: Approved installation and integrity verification

**Files for the selected disabled route:**
- Create: none
- Modify: none
- Test: `tests/safety/test_gitnexus_development_tooling.py`

**Conditional ENABLED-only files:**
- Generate: `tools/gitnexus/pnpm-lock.yaml`
- Modify: `tools/gitnexus/package.json` only through the exact pnpm command;
  its reviewed dependency value must remain byte-for-byte `1.6.9`
- Generate and ignore: `tools/gitnexus/node_modules/`

**Interfaces:**
- Consumes: exact pnpm 11.9.0, exact package manifest, lifecycle allowlist,
  supply-chain record, one-time approval, and local pnpm content store
- Produces conditionally: a generated exact transitive lock, one ignored
  project-local installation, local launcher, and post-acquisition integrity
  evidence; it produces no Python, product, build, or runtime dependency

- [ ] **Step 1: Prove the disabled route performs no acquisition**

```powershell
$prohibitedPaths = @(
    "tools\gitnexus\package.json",
    "tools\gitnexus\pnpm-lock.yaml",
    "tools\gitnexus\node_modules"
)
foreach ($relativePath in $prohibitedPaths) {
    if (Test-Path -LiteralPath $relativePath) {
        throw "Disabled outcome contains a partial installation: $relativePath"
    }
}
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_disabled_outcome_has_no_partial_tooling -q
```

Expected for 1.6.9: exit `0`; no approval request is made, pnpm is not invoked,
and no package, lock, launcher, or installation exists.

- [ ] **Step 2: Add the lock-to-integrity test and confirm red**

On `ENABLED_CANDIDATE`, append this exact test:

```python
def test_candidate_lock_binds_exact_gitnexus_integrity(
    repository_root: Path,
) -> None:
    lock_path = repository_root / "tools/gitnexus/pnpm-lock.yaml"
    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
        assert not lock_path.exists()
        return

    lock_text = lock_path.read_text(encoding="utf-8")
    assert "lockfileVersion: '9.0'" in lock_text
    importer = re.search(
        r"(?ms)^importers:\r?\n  \.:\r?\n(?P<body>.*?)(?=^[^ ]|\Z)",
        lock_text,
    )
    assert importer is not None
    assert re.search(
        r"(?ms)^    dependencies:.*?^      gitnexus:\r?\n"
        r"        specifier: 1\.6\.9\r?\n"
        r"        version: 1\.6\.9(?:\([^\r\n]+\))?$",
        importer.group("body"),
    )
    package = re.search(
        r"(?ms)^  gitnexus@1\.6\.9:\r?\n(?P<body>.*?)(?=^  \S|^[^ ]|\Z)",
        lock_text,
    )
    assert package is not None
    assert _manifest(repository_root)["dist_integrity"] in package.group("body")
    assert set(re.findall(r"(?m)^  gitnexus@([^:]+):", lock_text)) == {"1.6.9"}
```

Run the test and expect exit `1` because the lock is absent. This step is not
run on the selected disabled route.

- [ ] **Step 3: Generate the lock offline or disable**

```powershell
pnpm.cmd --dir .\tools\gitnexus install --lockfile-only --offline --ignore-scripts
```

Expected: exit `0` and a generated lock without `node_modules` or lifecycle
execution. If the local store cannot resolve the complete graph, remove only
the incomplete lock and route disabled. Never resolve a lock online, copy one
from another project, or hand-edit it.

- [ ] **Step 4: Validate, review, and commit the lock before acquisition**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_candidate_lock_binds_exact_gitnexus_integrity -q
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
git diff --check
git add tests/safety/test_gitnexus_development_tooling.py tools/gitnexus/pnpm-lock.yaml
git diff --cached --check
git diff --cached
git commit -m "chore: lock project-local gitnexus tooling"
git status --short
```

Expected: every command exits `0`; the test binds the importer pin and the
`gitnexus@1.6.9` package resolution to the manifest SHA-512 integrity; the
generated lock and its test are independently reviewed and committed; status
is clean before approval.

- [ ] **Step 5: Present the one frozen acquisition command and wait**

Display exactly:

```powershell
pnpm.cmd --dir .\tools\gitnexus install --frozen-lockfile --ignore-scripts
```

This one-time command may contact the registry but may consume only the
already-reviewed lock and cannot run lifecycle scripts. Ask for approval of
this exact command only. Decline, lock drift, missing offline lock, or a need
to enable scripts routes disabled.

- [ ] **Step 6: Execute the approved boundary and verify locally**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\install.ps1 -ApprovedExactAcquisition -Phase Preflight
$lockHashBefore = (
    Get-FileHash -LiteralPath ".\tools\gitnexus\pnpm-lock.yaml" -Algorithm SHA256
).Hash
pnpm.cmd --dir .\tools\gitnexus install --frozen-lockfile --ignore-scripts
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$lockHashAfter = (
    Get-FileHash -LiteralPath ".\tools\gitnexus\pnpm-lock.yaml" -Algorithm SHA256
).Hash
if ($lockHashAfter -ne $lockHashBefore) {
    throw "The approved frozen acquisition changed the reviewed lockfile"
}
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\install.ps1 -ApprovedExactAcquisition -Phase Postflight
pnpm.cmd --dir .\tools\gitnexus install --frozen-lockfile --offline --ignore-scripts
pnpm.cmd --dir .\tools\gitnexus list --depth 0 --json
pnpm.cmd --dir .\tools\gitnexus store status
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 version
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 doctor
git diff --exit-code -- tools/gitnexus/package.json tools/gitnexus/pnpm-lock.yaml
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
git status --short
```

Expected: every command exits `0`; the only network-capable invocation is the
exact package-manager command shown and approved in Step 5; preflight and
postflight validation cannot install anything; package and lock remain
byte-for-byte committed; only ignored `node_modules` is added; version is
exactly 1.6.9; doctor proves the native runtime can start without lifecycle
scripts or a network; both verifiers pass and status is clean. Network
authorization ends when the approved frozen install returns.

- [ ] **Step 7: Persist the clean Task 4 checkpoint**

On a successful enabled route, update the ignored ledger exactly:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.completed_tasks = @(1, 2, 3, 4)
$ledger.resume_task = 5
$ledger.resume_step = 1
$ledger.repository_status = "CLEAN"
$ledger | Add-Member -NotePropertyName acquisition_network_boundary_closed `
    -NotePropertyValue $true -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
git status --short
```

Expected: exit `0`; status is empty and the ledger resumes at Task 5 without
replaying the approved acquisition.

- [ ] **Step 8: Fail safely on any acquisition or integrity defect**

On failure, if `.codex/config.toml` contains `enabled = true`, apply the exact
one-line `enabled = true` to `enabled = false` patch from Task 7 letter A. Ask
the user to close all ChatGPT Desktop windows so the host terminates its
non-required child. Do not enumerate ambient process command lines, kill an
unidentified process, or inspect environment values. Continue only after the
host is closed; if any cleanup target is locked, stop and ask the user to close
the owning application instead of forcing or guessing. Then resolve each
cleanup target and prove it is below the current worktree root before removal:

```powershell
$repositoryRoot = (git rev-parse --show-toplevel).Trim()
$cleanupTargets = @(
    ".gitnexus",
    ".gitnexusrc",
    ".gitnexusignore",
    ".codex\config.toml",
    "tools\gitnexus\node_modules",
    "tools\gitnexus\package.json",
    "tools\gitnexus\pnpm-workspace.yaml",
    "tools\gitnexus\pnpm-lock.yaml",
    "tools\gitnexus\scripts"
)
foreach ($relativeTarget in $cleanupTargets) {
    $candidate = Join-Path -Path $repositoryRoot -ChildPath $relativeTarget
    if (-not (Test-Path -LiteralPath $candidate)) {
        continue
    }
    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    $prefix = $repositoryRoot.TrimEnd("\") + "\"
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing cleanup outside the worktree: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
```

Do not remove `tools/gitnexus/README.md` or `supply-chain.json`. Before cleanup,
set `$failureReasonCode` to exactly one inspected reason below and set
`$invalidatedControls` to the exact subset of the five control names disproved
by the failure (or `@()` when none was disproved):

```powershell
$allowedFailureReasons = @(
    "NODE_REQUIREMENT_NOT_MET",
    "PACKAGE_MANAGER_UNAVAILABLE",
    "PACKAGE_IDENTITY_UNVERIFIED",
    "PACKAGE_INTEGRITY_UNVERIFIED",
    "LICENSE_INCOMPATIBLE_OR_UNCLEAR",
    "OFFLINE_LOCK_GENERATION_FAILED",
    "INSTALLATION_DECLINED",
    "INSTALLATION_FAILED",
    "NATIVE_DEPENDENCY_INCOMPATIBLE",
    "PROJECT_LOCAL_WRAPPER_UNPROVEN",
    "READ_ONLY_MODE_UNPROVEN",
    "TOOL_ALLOWLIST_UNPROVEN",
    "SOURCE_RUNTIME_EXCLUSIONS_UNPROVEN",
    "OFFLINE_EXTENSION_BEHAVIOR_UNPROVEN",
    "CODEX_MCP_UNSTABLE_OR_UNSAFE"
)
$controlNames = @(
    "GITNEXUS_MCP_READ_ONLY",
    "GITNEXUS_MCP_ALLOWED_REPOS",
    "GITNEXUS_MCP_DEFAULT_REPO",
    "GITNEXUS_MCP_DEFAULT_MAX_TOKENS",
    "server_side_seven_tool_allowlist"
)
if ($failureReasonCode -notin $allowedFailureReasons) {
    throw "Unreviewed disabled-outcome reason: $failureReasonCode"
}
if (@($invalidatedControls | Where-Object { $_ -notin $controlNames }).Count) {
    throw "Unreviewed invalidated MCP control"
}
$controlEvidence = [ordered]@{}
foreach ($controlName in $controlNames) {
    $controlEvidence[$controlName] = $controlName -notin $invalidatedControls
}
$disabledOutcome = [ordered]@{
    schema_version = 1
    stage = "project-1-stage-2"
    outcome = "DISABLED_WITH_EVIDENCE"
    stage_3_planning_permitted = $true
    decision_date = [DateTime]::UtcNow.ToString(
        "yyyy-MM-dd",
        [System.Globalization.CultureInfo]::InvariantCulture
    )
    package_name = "gitnexus"
    package_version = "1.6.9"
    reason_codes = @($failureReasonCode)
    required_mcp_controls = $controlEvidence
    project_state = [ordered]@{
        package_installed = $false
        codex_mcp_configured = $false
        index_present = $false
        partial_configuration_present = $false
    }
    fallback = @(
        "review_normative_sources",
        "search_source_and_references_with_rg",
        "inspect_base_to_head_diff",
        "run_ordinary_offline_verification"
    )
}
$disabledOutcomeJson = $disabledOutcome | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path $repositoryRoot -ChildPath "tools\gitnexus\outcome.json"),
    $disabledOutcomeJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

The control map starts from the Task 1 candidate proof and records any later
contradiction as false; it never fabricates a passing control. Preserve both
common `.gitignore` rules for `/.superpowers/sdd/` and the project-local
`node_modules`; neither is partial GitNexus configuration.

Stage only the bounded tracked deletions before running outcome-aware tests.
This updates the index view consumed by `_tracked_paths()` without creating a
commit; otherwise deleted files would remain visible through
`git ls-files --cached` and the disabled-state tests would correctly reject the
still-stale index:

```powershell
$trackedCleanupPaths = @(
    ".gitnexusrc",
    ".gitnexusignore",
    ".codex/config.toml",
    "tools/gitnexus/package.json",
    "tools/gitnexus/pnpm-workspace.yaml",
    "tools/gitnexus/pnpm-lock.yaml",
    "tools/gitnexus/scripts"
)
foreach ($trackedCleanupPath in $trackedCleanupPaths) {
    $trackedMatch = @(git ls-files -- $trackedCleanupPath)
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    if ($trackedMatch.Count -ne 0 -or
        (Test-Path -LiteralPath $trackedCleanupPath)) {
        git add -A -- $trackedCleanupPath
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
}
```

In the feature worktree only, reconcile a roadmap that has already reached
`ENABLED`. An earlier failure leaves the baseline roadmap untouched so Task 7
Step 5 can apply its complete baseline-to-disabled patch. A failure after Task
7 Step 10 uses this exact UTF-8-safe `ENABLED`-to-disabled transition:

```powershell
$roadmapPath = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
$enabledRow = '| 2 — Guarded GitNexus Development Tooling | Approved and executed | `ENABLED`: exact package, local index, project MCP, exclusions, and bounded read-only tools verified | Complete; ordinary offline verification also passes with GitNexus disabled |'
$disabledRow = '| 2 — Guarded GitNexus Development Tooling | Approved and executed | `DISABLED_WITH_EVIDENCE`: pinned 1.6.9 lacks mandatory MCP controls; no partial tooling remains | Complete; ordinary offline verification and manual fallback recorded |'
$roadmapAbsolutePath = Join-Path -Path $repositoryRoot -ChildPath $roadmapPath
$roadmapText = [System.IO.File]::ReadAllText(
    $roadmapAbsolutePath,
    [System.Text.UTF8Encoding]::new($false)
)
if ($roadmapText.Contains($enabledRow)) {
    $roadmapText = $roadmapText.Replace($enabledRow, $disabledRow)
    [System.IO.File]::WriteAllText(
        $roadmapAbsolutePath,
        $roadmapText,
        [System.Text.UTF8Encoding]::new($false)
    )
}
```

Then remove only an empty `.codex/` directory, update the ignored continuation
ledger, and prove the uncommitted cleanup. Do not commit here: Task 7 must make
the outcome, roadmap, operator guidance, safety test, and all enabled-only
deletions consistent in one independently reviewed terminal commit.

```powershell
if ((Test-Path -LiteralPath ".codex" -PathType Container) -and
    -not (Get-ChildItem -LiteralPath ".codex" -Force)) {
    Remove-Item -LiteralPath ".codex" -Force
}
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$task7AlreadyStarted = Test-Path -LiteralPath "tools/gitnexus/README.md"
$roadmapPath = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
$disabledRow = '| 2 — Guarded GitNexus Development Tooling | Approved and executed | `DISABLED_WITH_EVIDENCE`: pinned 1.6.9 lacks mandatory MCP controls; no partial tooling remains | Complete; ordinary offline verification and manual fallback recorded |'
$roadmapText = [System.IO.File]::ReadAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $roadmapPath),
    [System.Text.UTF8Encoding]::new($false)
)
$disabledRoadmapReady = $roadmapText.Contains($disabledRow)
$ledger.route = "DISABLED_WITH_EVIDENCE"
$ledger.terminal_outcome = "DISABLED_WITH_EVIDENCE"
$ledger.resume_task = 7
$ledger.resume_step = if ($task7AlreadyStarted -and $disabledRoadmapReady) {
    7
}
elseif ($task7AlreadyStarted) {
    5
}
else {
    1
}
$ledger.repository_status = "DIRTY_EXPECTED"
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_disabled_outcome_has_no_partial_tooling -q
git diff --check
git status --short
```

Expected: every bounded check exits `0`; the ignored ledger selects Task 7
Step 1 for an early failure, Step 5 when documentation exists but the roadmap
is still baseline, or Step 7 when the feature-worktree roadmap is already
terminal disabled. The visible status contains only bounded staged
enabled-file deletions and terminal outcome work; no cleanup commit exists yet.
The complete ordinary verifier is deliberately deferred until Task 7 makes all
operator documentation consistent. Resume exactly at the recorded ledger step.
Do not purge the user's shared pnpm content store or rewrite an earlier reviewed
commit.

**Focused verification:** Disabled route proves no package state exists.
Conditional enabled route proves the exact top-level version, transitive lock
integrity, lifecycle allowlist, local launcher, and frozen offline reinstall.

**Broader verification:** After Task 7 makes terminal evidence, roadmap, and
operator guidance consistent, both the optional tooling verifier and complete
ordinary verifier pass; the ordinary verifier remains sufficient by itself.

**Security review:** Review the generated lock, package lifecycle list, native
dependency set, and local launcher metadata. Confirm there was one bounded
approved network command, no global install, no package-manager replacement,
and no background updater.

**Commit:** The selected disabled route creates no Task 4 change and no commit.
Do not create an empty commit. On a gate-complete enabled route, the candidate
manifest/configuration commit was completed in Task 2 and the generated lock
commit was completed in Step 4 above. The approved installation creates only
ignored `node_modules`, so a successful Task 4 creates no additional tracked
change or commit. A failed candidate remains deliberately uncommitted until
Task 7's exact terminal-outcome commit stages and reviews every cleanup change.

**Independent review gate:** A reviewer must compare package.json, pnpm lock,
installed package metadata, supply-chain identity, lifecycle allowlist, and
command transcript. Any mismatch disables the integration.

## Task 5: Safe local index creation and CLI smoke verification

**Files for the selected disabled route:**
- Create: none
- Modify: none
- Test: absence of `.gitnexus/` and all generated instructions

**Conditional ENABLED-only generated state:**
- Generate and ignore: `.gitnexus/`
- Modify tracked source: none

**Interfaces:**
- Consumes conditionally: exact local wrapper, `.gitnexusrc`,
  `.gitnexusignore`, reviewed installation, tracked-source hash snapshot, and
  registry name `crypto-trading-lab`
- Produces conditionally: one disposable ignored local index plus bounded CLI
  smoke evidence; produces no tracked generated instructions, skills, hooks,
  reports, product data, or runtime state

- [ ] **Step 1: Prove the disabled route has no index or generated files**

```powershell
if (Test-Path -LiteralPath ".gitnexus") {
    throw "Disabled outcome contains a local GitNexus index"
}
git status --short
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_disabled_outcome_has_no_partial_tooling -q
```

Expected for 1.6.9: exit `0`; no index exists, only planned tracked evidence
is present, and no GitNexus command runs. Record Steps 2-7 as
`NOT_RUN_CONTROL_GATE_FAILED`.

- [ ] **Step 2: On an enabled route, snapshot protected tracked files and status**

```powershell
$protectedPaths = @(
    "AGENTS.md",
    "README.md",
    "docs/superpowers/specs/2026-08-10-engine-neutral-core-design.md",
    "docs/decisions/0001-gitnexus-development-tooling.md",
    "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md",
    "docs/superpowers/plans/2026-08-10-project-1-foundation-implementation-plan.md"
)
$hashesBefore = @{}
foreach ($path in $protectedPaths) {
    $hashesBefore[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
$statusBefore = @(git status --short)
$trackedPathsBefore = @(git ls-files --cached)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inventory tracked files before analysis"
}
if (Test-Path -LiteralPath ".gitnexus") {
    throw "A local GitNexus index already exists before first analysis"
}
$forbiddenGeneratedPaths = @(
    ".agents\skills\gitnexus",
    ".claude\skills\gitnexus",
    ".codex\skills\gitnexus",
    ".github\copilot-instructions.md",
    "CLAUDE.md",
    "GEMINI.md"
)
foreach ($generatedPath in $forbiddenGeneratedPaths) {
    if (Test-Path -LiteralPath $generatedPath) {
        throw "Generated agent context exists before analysis: $generatedPath"
    }
}
$agentMarkerPattern = '(?i)<!--[^>]*gitnexus|(?:BEGIN|END)\s+GITNEXUS'
$agentMarkersBefore = @(
    Select-String -LiteralPath "AGENTS.md" -Pattern $agentMarkerPattern
)
if ($agentMarkersBefore.Count -ne 0) {
    throw "AGENTS.md contains a GitNexus-generated marker before analysis"
}
$gitCommonDirectory = (git rev-parse --git-common-dir).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitCommonDirectory)) {
    throw "Unable to resolve shared Git metadata before analysis"
}
$resolvedGitCommonDirectory = (
    Resolve-Path -LiteralPath $gitCommonDirectory
).Path
$hookRoot = Join-Path -Path $resolvedGitCommonDirectory -ChildPath "hooks"
$hookHashesBefore = @{}
if (Test-Path -LiteralPath $hookRoot -PathType Container) {
    foreach ($hook in Get-ChildItem -LiteralPath $hookRoot -File) {
        $hookHashesBefore[$hook.Name] = (
            Get-FileHash -LiteralPath $hook.FullName -Algorithm SHA256
        ).Hash
        if (Select-String -LiteralPath $hook.FullName -Pattern '(?i)gitnexus' -Quiet) {
            throw "A GitNexus hook exists before analysis: $($hook.Name)"
        }
    }
}
```

Expected: every command exits `0`; no index, generated skill, generated context
file, GitNexus hook, or generated AGENTS marker exists; and the exact protected
hash, tracked-path, hook-hash, and status snapshots are retained in the active
SDD session. Do not write a path- or username-bearing snapshot file.

- [ ] **Step 3: Prove ignore boundaries before analysis**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_candidate_package_and_static_configuration_are_exact -q
```

Expected: exit `0`. The test reads `.gitnexusignore` itself, requires the exact
reviewed rule set, and applies its standard-library matcher to rooted runtime,
sensitive, and preserved-source probes. `git check-ignore` is intentionally not
used because it evaluates `.gitignore`, not `.gitnexusignore`. Before enabling,
review the exact pinned GitNexus ignore-parser source and prove it implements
the anchored/directory/glob semantics mirrored by the test; parser drift or
ambiguity disables the candidate.

- [ ] **Step 4: Create the local index only through the approved wrapper**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 analyze
```

Expected: exit `0`; analysis uses `indexOnly`, skips generated agent context and
skills, disables embeddings, loads optional database extensions only from
local content, creates `.gitnexus/`, and creates no other tracked or unignored
path. There is no remote model, extension download, server, web UI, publishing,
or hook action.

- [ ] **Step 5: Prove tracked source was not mutated**

```powershell
foreach ($path in $protectedPaths) {
    $hashAfter = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($hashAfter -ne $hashesBefore[$path]) {
        throw "GitNexus changed protected tracked source: $path"
    }
}
foreach ($generatedPath in $forbiddenGeneratedPaths) {
    if (Test-Path -LiteralPath $generatedPath) {
        throw "Analysis generated prohibited agent context: $generatedPath"
    }
}
$agentMarkersAfter = @(
    Select-String -LiteralPath "AGENTS.md" -Pattern $agentMarkerPattern
)
if ($agentMarkersAfter.Count -ne 0) {
    throw "Analysis generated an AGENTS.md marker"
}
$hookHashesAfter = @{}
if (Test-Path -LiteralPath $hookRoot -PathType Container) {
    foreach ($hook in Get-ChildItem -LiteralPath $hookRoot -File) {
        $hookHashesAfter[$hook.Name] = (
            Get-FileHash -LiteralPath $hook.FullName -Algorithm SHA256
        ).Hash
        if (Select-String -LiteralPath $hook.FullName -Pattern '(?i)gitnexus' -Quiet) {
            throw "Analysis generated a GitNexus hook: $($hook.Name)"
        }
    }
}
$hookNamesBefore = @($hookHashesBefore.Keys | Sort-Object)
$hookNamesAfter = @($hookHashesAfter.Keys | Sort-Object)
if (($hookNamesBefore -join "`n") -ne ($hookNamesAfter -join "`n")) {
    throw "Analysis changed the Git hook file set"
}
foreach ($hookName in $hookHashesBefore.Keys) {
    if ($hookHashesAfter[$hookName] -ne $hookHashesBefore[$hookName]) {
        throw "Analysis changed a Git hook: $hookName"
    }
}
$null = git check-ignore -- .gitnexus
if ($LASTEXITCODE -ne 0) {
    throw ".gitnexus is not ignored"
}
$trackedPathsAfter = @(git ls-files --cached)
if ($LASTEXITCODE -ne 0 -or
    (Compare-Object $trackedPathsBefore $trackedPathsAfter)) {
    throw "Analysis changed the tracked file set"
}
$statusAfter = @(git status --short)
if (Compare-Object $statusBefore $statusAfter) {
    throw "Analysis changed tracked or visible untracked status"
}
$statusAfter
```

Expected: every protected hash is unchanged, `.gitnexus/` is ignored, and
the tracked file set and exact status equal their pre-analysis snapshots. The
explicit path, AGENTS-marker, and hook checks prove no generated skill, context
file, AGENTS block, or Git hook appeared.

- [ ] **Step 6: Run the exact bounded CLI smoke commands**

```powershell
$wrapper = ".\tools\gitnexus\scripts\gitnexus.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper version
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper doctor
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper status
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper query
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper context
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper impact
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper trace
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper detect-changes
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper check
```

Expected: every command exits `0`; each fixed wrapper profile refers only to
`crypto-trading-lab`; the trace joins the named test and CLI function when
both symbols are indexed; and check returns its bounded structural and cycle
findings. No check result is interpreted as a policy or correctness proof.
Output is advisory and is never test evidence.

- [ ] **Step 7: Run index-aware and ordinary verification**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1 -RequireIndex
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
git status --short
```

Expected: every command exits `0`; the optional verifier sees a healthy local
index, the ordinary verifier remains complete and offline, and tracked status
did not change during index creation.

- [ ] **Step 8: Persist the clean Task 5 checkpoint**

On a successful enabled route, update the ignored ledger exactly:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.completed_tasks = @(1, 2, 3, 4, 5)
$ledger.resume_task = 6
$ledger.resume_step = 1
$ledger.repository_status = "CLEAN"
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
git status --short
```

Expected: exit `0`; status remains empty and a resumed execution starts at
Task 6 without rebuilding the already verified index.

**Focused verification:** Disabled route proves index absence. Conditional
enabled route proves exclusions, exact protected hashes, registry identity,
and each bounded CLI command.

**Broader verification:** Both verifier scripts pass, with ordinary project
verification independent of the index.

**Security review:** Confirm no sensitive/runtime path was indexed, no tracked
source changed, no generated instruction/skill/hook exists, no embeddings or
extension acquisition occurred, and no output is treated as authoritative.

**Commit:** No Task 5 commit is permitted because the only enabled output is an
ignored disposable index and the disabled route produces nothing. Do not
create an empty index-verification commit.

**Independent review gate:** A reviewer compares before/after hashes, status,
ignore probes, local registry identity, and every bounded command. Any
unexplained mutation or cross-repository result locks disabled cleanup.

## Task 6: Project-scoped Codex MCP configuration and restart-boundary verification

**Files for the selected disabled route:**
- Create: none
- Modify: none
- Test: absence of `.codex/config.toml` and a healthy Codex host without the
  server

**Conditional ENABLED-only files:**
- Create: `.codex/config.toml`
- Consume: `tools/gitnexus/scripts/gitnexus-mcp.ps1`

**Interfaces:**
- Consumes conditionally: a gate-complete exact package, healthy local index,
  proven wrapper controls, current official Codex MCP syntax, and the exact
  seven-tool allowlist
- Produces conditionally: a non-required project-scoped STDIO server named
  `gitnexus`, restart-safe SDD continuation evidence, exact tool discovery, and
  seven bounded advisory MCP smoke results

- [ ] **Step 1: Prove the disabled route leaves Codex unconfigured**

```powershell
if (Test-Path -LiteralPath ".codex\config.toml") {
    throw "Disabled outcome contains a project-scoped MCP configuration"
}
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_disabled_outcome_has_no_partial_tooling -q
git status --short
```

Expected for 1.6.9: exit `0`; Codex continues without a project server, no
restart is required, and Steps 2-8 are recorded as
`NOT_RUN_CONTROL_GATE_FAILED`.

- [ ] **Step 2: On an enabled route, run the MCP configuration assertion red**

Append this exact outcome-aware static test to
`tests/safety/test_gitnexus_development_tooling.py`:

```python
def test_enabled_codex_mcp_configuration_is_exact(repository_root: Path) -> None:
    config_path = repository_root / ".codex/config.toml"
    if _execution_route(repository_root) == "DISABLED_WITH_EVIDENCE":
        assert not config_path.exists()
        return

    assert _load_toml(config_path) == {
        "mcp_servers": {
            "gitnexus": {
                "command": "powershell.exe",
                "args": [
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    "tools/gitnexus/scripts/gitnexus-mcp.ps1",
                ],
                "cwd": ".",
                "enabled": True,
                "required": False,
                "startup_timeout_sec": 20,
                "tool_timeout_sec": 60,
                "enabled_tools": [
                    "list_repos",
                    "query",
                    "context",
                    "impact",
                    "trace",
                    "detect_changes",
                    "check",
                ],
                "default_tools_approval_mode": "writes",
                "env": {
                    "GITNEXUS_MCP_READ_ONLY": "1",
                    "GITNEXUS_MCP_ALLOWED_REPOS": "crypto-trading-lab",
                    "GITNEXUS_MCP_DEFAULT_REPO": "crypto-trading-lab",
                    "GITNEXUS_MCP_DEFAULT_MAX_TOKENS": "8000",
                },
            }
        }
    }
```

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_enabled_codex_mcp_configuration_is_exact -q
```

Expected before `.codex/config.toml`: exit `1` because the project MCP entry is
absent. This is a static check and does not start a server.

- [ ] **Step 3: Create the exact conditional Codex project configuration**

Conditional `.codex/config.toml`:

```toml
[mcp_servers.gitnexus]
command = "powershell.exe"
args = [
  "-NoLogo",
  "-NoProfile",
  "-NonInteractive",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  "tools/gitnexus/scripts/gitnexus-mcp.ps1",
]
cwd = "."
enabled = true
required = false
startup_timeout_sec = 20
tool_timeout_sec = 60
enabled_tools = [
  "list_repos",
  "query",
  "context",
  "impact",
  "trace",
  "detect_changes",
  "check",
]
default_tools_approval_mode = "writes"

[mcp_servers.gitnexus.env]
GITNEXUS_MCP_READ_ONLY = "1"
GITNEXUS_MCP_ALLOWED_REPOS = "crypto-trading-lab"
GITNEXUS_MCP_DEFAULT_REPO = "crypto-trading-lab"
GITNEXUS_MCP_DEFAULT_MAX_TOKENS = "8000"
```

No absolute path, trust setting, credential, fifth environment variable, or
global command is permitted. `required = false` is mandatory. The approval
mode relies on proven read-only annotations/behavior; if any allowlisted tool
requests write approval or performs a mutation, disable the integration.

- [ ] **Step 4: Turn the static configuration test green and prove path behavior**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py::test_enabled_codex_mcp_configuration_is_exact -q
codex mcp list
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1 -RequireIndex
```

Expected: every command exits `0`; the static test proves exact fields, four
environment controls, `required = false`, and only seven enabled tools; Codex
lists the project-scoped server from the external worktree; the relative
script argument and wrapper-owned root resolution select this worktree rather
than the main checkout. If Codex resolves `cwd = "."` or the script path
ambiguously, do not commit an absolute path; route to disabled cleanup.

- [ ] **Step 5: Commit the complete configuration before host restart**

```powershell
git add .codex/config.toml tests/safety/test_gitnexus_development_tooling.py
git diff --cached --check
git diff --cached
git commit -m "chore: configure optional gitnexus mcp"
git status --short
```

Expected: commit succeeds with exactly `.codex/config.toml` and the new static
configuration test; status is clean. The package, wrappers, prior static
policy, local index, and ordinary verification have already passed and are
committed where applicable.

- [ ] **Step 6: Record the restart boundary without replaying work**

Before pausing, write the exact non-sensitive boundary to the ignored ledger:

```powershell
$status = @(git status --short)
if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
    throw "The worktree must be clean before the host restart"
}
$preRestartCommit = (git rev-parse HEAD).Trim()
if ([string]::IsNullOrWhiteSpace($preRestartCommit)) {
    throw "Unable to record the pre-restart commit"
}
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.completed_tasks = @(1, 2, 3, 4, 5)
$ledger.resume_task = 6
$ledger.resume_step = 7
$ledger.repository_status = "CLEAN"
$ledger.pre_restart_commit = $preRestartCommit
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "CHATGPT_DESKTOP_RESTART_REQUIRED" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: exit `0`; the ledger retains branch
`project-1-stage-2-gitnexus-tooling`, route `ENABLED_CANDIDATE`, Tasks 1-5,
resume point Task 6 Step 7, the exact pre-restart commit, and clean status.

Do not record an absolute worktree path or environment value. Ask the user to
close every ChatGPT Desktop window, reopen the application, return to this
task/worktree, and resume at Task 6 Step 7. Do not rerun Tasks 1-5 merely
because the host restarted.

- [ ] **Step 7: Inspect MCP discovery after restart**

After the user returns, run read-only state checks:

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
codex mcp list
```

Then inspect `/mcp` in ChatGPT Desktop. Expected: Git status is clean; branch
and commit equal the ledger; server `gitnexus` is healthy but non-required;
exactly `list_repos`, `query`, `context`, `impact`, `trace`, `detect_changes`,
and `check` are available; no other GitNexus tool is exposed. If the host fails
to start, server fails, extra tools appear, an approval annotation is unsafe,
or the wrong repository is selected, keep `required = false`, disable/remove
the entry, clean partial state, and record `DISABLED_WITH_EVIDENCE`.

- [ ] **Step 8: Make the exact bounded MCP calls**

Invoke the seven discovered tools through Codex with these exact JSON argument
objects, one at a time:

```json
{"limit":10,"offset":0}
{"search_query":"version-only command","limit":5,"include_content":false,"repo":"crypto-trading-lab"}
{"name":"main","file_path":"src/crypto_lab/cli/main.py","include_content":false,"repo":"crypto-trading-lab"}
{"target":"main","direction":"upstream","file_path":"src/crypto_lab/cli/main.py","maxDepth":3,"includeTests":false,"limit":25,"repo":"crypto-trading-lab"}
{"from":"test_main_without_arguments_prints_help_and_succeeds","to":"main","from_file":"tests/unit/test_cli.py","to_file":"src/crypto_lab/cli/main.py","maxDepth":10,"includeTests":true,"repo":"crypto-trading-lab"}
{"scope":"compare","base_ref":"main","repo":"crypto-trading-lab"}
{"cycles":true,"repo":"crypto-trading-lab"}
```

Apply the objects in allowlist order: `list_repos`, `query`, `context`,
`impact`, `trace`, `detect_changes`, `check`. Expected: every call is bounded,
targets only `crypto-trading-lab`, returns without repository or index mutation,
and does not expose another repository. `check` reports structural/cycle data,
not a correctness or policy judgment. Save only a non-sensitive summary in the
SDD ledger; GitNexus output remains advisory.

- [ ] **Step 9: Re-run verification and status after MCP smoke calls**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1 -RequireIndex
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
git status --short
```

Expected: all commands exit `0` and status is clean. MCP calls changed neither
tracked source nor ordinary verification behavior.

Persist the post-restart checkpoint exactly:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$currentCommit = (git rev-parse HEAD).Trim()
if ($currentCommit -ne $ledger.pre_restart_commit) {
    throw "The branch changed across the restart boundary"
}
$ledger.completed_tasks = @(1, 2, 3, 4, 5, 6)
$ledger.resume_task = 7
$ledger.resume_step = 1
$ledger.repository_status = "CLEAN"
$ledger.boundary = "CHATGPT_DESKTOP_RESTART_COMPLETED"
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: exit `0`; a later session resumes at Task 7 and does not replay the
package, index, configuration, or restart work.

**Focused verification:** Disabled route proves no MCP file/server exists.
Conditional enabled route proves static TOML, external-worktree root
resolution, host reload, exact discovery, and seven bounded calls.

**Broader verification:** Optional tooling and complete ordinary verification
both pass after restart and MCP use.

**Security review:** Confirm the configuration contains exactly four permitted
non-secret environment variables, no absolute/private path, no credential,
only the seven tools, non-required startup, and no unreviewed server/tool.

**Commit:** The selected disabled route creates no Task 6 change and no commit.
Do not create an empty restart commit. The conditional enabled commit is made
in Step 5 with exact message `chore: configure optional gitnexus mcp`.

**Independent review gate:** A fresh reviewer inspects TOML, wrapper, discovery,
restart ledger, every MCP input/result summary, post-call status, and ordinary
verification. Client filtering is accepted only after the package independently
proves server-side ADR controls.

## Task 7: Optionality, rollback, outcome documentation, and final acceptance

**Files for both outcomes:**
- Create: `tools/gitnexus/README.md`
- Modify: `tests/safety/test_gitnexus_development_tooling.py`
- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`
- Create: `tools/gitnexus/outcome.json` only on the conditional enabled route

**Interfaces:**
- Consumes: every Task 1-6 decision, review, commit, optionality proof, the
  unchanged ordinary verifier, and `stage2BaseCommit`
- Produces: one final outcome, inert operator evidence, manual fallback,
  outcome-aware repository guidance, fresh verification, a fully reviewed
  base-to-HEAD diff, and a clean branch eligible for direct local fast-forward
  integration

- [ ] **Step 1: Add the final evidence-directory assertion and confirm red**

Apply this exact patch to
`tests/safety/test_gitnexus_development_tooling.py` immediately after
`test_repository_local_sdd_ledger_is_ignored`:

```diff
 def test_repository_local_sdd_ledger_is_ignored(repository_root: Path) -> None:
     gitignore = (repository_root / ".gitignore").read_text(encoding="utf-8")
     entries = set(gitignore.splitlines())

     assert "/.superpowers/sdd/" in entries
     assert "/tools/gitnexus/node_modules/" in entries
+
+
+def test_tooling_evidence_directory_matches_outcome(repository_root: Path) -> None:
+    route = _execution_route(repository_root)
+    prefix = "tools/gitnexus/"
+    relative_files = {
+        path.removeprefix(prefix)
+        for path in _tracked_paths(repository_root)
+        if path.startswith(prefix)
+    }
+    enabled_files = {
+        "README.md",
+        "package.json",
+        "pnpm-lock.yaml",
+        "pnpm-workspace.yaml",
+        "scripts/gitnexus-mcp.ps1",
+        "scripts/gitnexus.ps1",
+        "scripts/install.ps1",
+        "scripts/verify.ps1",
+        "supply-chain.json",
+    }
+
+    if route == "DISABLED_WITH_EVIDENCE":
+        assert relative_files == {
+            "README.md",
+            "outcome.json",
+            "supply-chain.json",
+        }
+    elif route == "ENABLED_CANDIDATE":
+        assert relative_files == enabled_files
+        assert _terminal_outcome(repository_root) is None
+    else:
+        assert route == "ENABLED"
+        assert relative_files == enabled_files | {"outcome.json"}
+
+    pyproject = _load_toml(repository_root / "pyproject.toml")
+    hatch = cast(dict[str, Any], pyproject["tool"])["hatch"]
+    build = cast(dict[str, Any], hatch["build"])
+    targets = cast(dict[str, Any], build["targets"])
+    sdist = cast(dict[str, Any], targets["sdist"])
+    include = cast(list[str], sdist["include"])
+    assert all(path != "/tools" and not path.startswith("/tools/") for path in include)
+    wheel = cast(dict[str, Any], targets["wheel"])
+    assert wheel["packages"] == ["src/crypto_lab"]
+
+
+def test_terminal_outcome_matches_roadmap_status(repository_root: Path) -> None:
+    route = _execution_route(repository_root)
+    roadmap = (
+        repository_root
+        / "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
+    ).read_text(encoding="utf-8")
+    enabled_row = (
+        "| 2 — Guarded GitNexus Development Tooling | Approved and executed | "
+        "`ENABLED`: exact package, local index, project MCP, exclusions, and "
+        "bounded read-only tools verified | Complete; ordinary offline "
+        "verification also passes with GitNexus disabled |"
+    )
+    disabled_row = (
+        "| 2 — Guarded GitNexus Development Tooling | Approved and executed | "
+        "`DISABLED_WITH_EVIDENCE`: pinned 1.6.9 lacks mandatory MCP controls; "
+        "no partial tooling remains | Complete; ordinary offline verification "
+        "and manual fallback recorded |"
+    )
+    if route == "ENABLED_CANDIDATE":
+        assert enabled_row not in roadmap
+        assert disabled_row not in roadmap
+        return
+
+    assert (
+        "**Status:** Approved planning decomposition; Stages 1 and 2 complete"
+        in roadmap
+    )
+    if route == "ENABLED":
+        assert enabled_row in roadmap
+        assert disabled_row not in roadmap
+    else:
+        assert route == "DISABLED_WITH_EVIDENCE"
+        assert disabled_row in roadmap
+        assert enabled_row not in roadmap
```

Run:

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
```

Expected for the selected disabled route: exit `1` because the required inert
`tools/gitnexus/README.md` and terminal roadmap status do not yet exist. No
executable runs. A conditional candidate remains green only while neither
terminal roadmap row exists; its final terminal row is tested after Step 10.

- [ ] **Step 2: Create the exact outcome-neutral operator evidence**

Create `tools/gitnexus/README.md` with exactly:

````markdown
# Guarded GitNexus Development Tooling

This directory records the optional Project 1 Stage 2 developer-tool decision.
It is outside the Python package and Hatch build inputs. GitNexus is never a
product, runtime, build, test, adapter, trading-engine, or acceptance
dependency.

## Outcome authority

- `supply-chain.json` records the exact reviewed package identity and official
  source identifiers.
- `outcome.json` records the single Stage 2 outcome and non-sensitive reason
  evidence.

When `outcome.json` says `DISABLED_WITH_EVIDENCE`, this directory contains only
`README.md`, `supply-chain.json`, and `outcome.json`. There is no package
manifest, pnpm lock, script, installation, MCP entry, or local index.

When `outcome.json` says `ENABLED`, use only the committed project-local
wrappers and exact lock. GitNexus output remains advisory. Never use a launcher
discovered through PATH or a user-profile package shim.

## Manual source, reference, and diff fallback

Run from the repository root:

```powershell
rg --files src tests scripts docs AGENTS.md README.md pyproject.toml
rg -n "crypto_lab|class |def |import |from " src tests
git log -20 --oneline --decorate
$stage2BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage2BaseCommit)) {
    throw "Unable to determine the review base"
}
git diff --name-status "$stage2BaseCommit..HEAD"
git diff "$stage2BaseCommit..HEAD"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

Read the approved specification and ADR before an architectural change. Trace
imports and references with `rg`, inspect the complete base-to-HEAD diff, run
focused tests, and finish with the complete offline verifier. This fallback
satisfies the roadmap's advisory-tool gate when GitNexus is disabled or
temporarily unhealthy.

## Removal boundary

The local graph is disposable. Removing an enabled integration means disabling
or removing the project MCP entry, stopping its project-local process, removing
the ignored `.gitnexus/` index and project-local `node_modules`, and then
removing enabled-only package/config/wrapper files in a reviewed change. The
ordinary Python project must continue to verify before and after removal.
````

The PowerShell variable in the fallback is set from the Stage 2 worktree's
recorded merge base before use. The file contains no machine path, username,
credential, or tool result.

- [ ] **Step 3: Apply the exact repository-instruction patch**

Apply this exact patch to `AGENTS.md`:

```diff
- During Stage 1, do not install, configure, or invoke GitNexus. After a separately approved Stage 2, keep it optional, project-scoped, read-only, advisory, and outside product, build, test, and runtime dependencies.
+- Read `tools/gitnexus/outcome.json` before any GitNexus action. When it records `DISABLED_WITH_EVIDENCE`, do not install, configure, or invoke GitNexus; use the documented manual source, reference, and diff fallback.
+- When `tools/gitnexus/outcome.json` records `ENABLED`, use only the committed project-local wrappers and exact lock. Never use a PATH-discovered or user-profile launcher, and keep GitNexus optional, project-scoped, proven read-only, advisory, and outside product, build, test, runtime, and acceptance dependencies.
+- GitNexus absence or failure must never block application implementation, tests, builds, reviews, runtime operation, acceptance, or Stage 3 planning.
```

Do not weaken the existing ambient-environment rule. The only possible MCP
environment-variable exception remains the four exact ADR controls.

- [ ] **Step 4: Apply the exact README patch**

Insert this section immediately before `## Architecture references` in
`README.md`:

````diff
+## Optional GitNexus developer context
+
+Project 1 Stage 2 records its exact governance outcome in
+[`tools/gitnexus/outcome.json`](tools/gitnexus/outcome.json) and its reviewed
+package identity in
+[`tools/gitnexus/supply-chain.json`](tools/gitnexus/supply-chain.json).
+GitNexus is optional, advisory developer tooling and is not needed to set up,
+verify, build, test, or run the Python project.
+
+When the outcome is `DISABLED_WITH_EVIDENCE`, no package, MCP entry, wrapper,
+or local index is present. Use the manual source, reference, and diff workflow
+in [`tools/gitnexus/README.md`](tools/gitnexus/README.md). When the outcome is
+`ENABLED`, use only its project-local committed wrappers and exact lock.
+
 ## Architecture references
````

- [ ] **Step 5: Apply the exact disabled roadmap status patch**

The selected 1.6.9 route must apply this patch to
`docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md`:

```diff
-**Status:** Approved planning decomposition; implementation has not started
+**Status:** Approved planning decomposition; Stages 1 and 2 complete
@@
-| 1 — Repository Foundation and Quality Gates | Created in this planning task; awaiting user review | Not started | Not evaluated |
-| 2 — Guarded GitNexus Development Tooling | Intentionally deferred until Stage 1 completion; its future plan must define both paths, and Stage 2 execution records and evidences exactly one | Not started | Not evaluated |
-| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Intentionally deferred until Stage 1 and the Stage 2 governance outcome are complete; either outcome permits planning | Not started | Not evaluated |
+| 1 — Repository Foundation and Quality Gates | Approved and executed | Complete at `56d029e8e6d3c67dc6309b267c74833a09d2e419` | Complete |
+| 2 — Guarded GitNexus Development Tooling | Approved and executed | `DISABLED_WITH_EVIDENCE`: pinned 1.6.9 lacks mandatory MCP controls; no partial tooling remains | Complete; ordinary offline verification and manual fallback recorded |
+| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Eligible for just-in-time planning after the completed Stage 2 governance decision | Not started | Not evaluated |
```

For a candidate enabled route, retain the complete alternative patch below in
this reviewed plan but do not apply any part of it until Step 10, after A-J
passes. This alternative updates the common status plus the Stage 1 and Stage 3
rows as well as the enabled Stage 2 row, so the terminal roadmap test never sees
a partial status transition:

```diff
-**Status:** Approved planning decomposition; implementation has not started
+**Status:** Approved planning decomposition; Stages 1 and 2 complete
@@
-| 1 — Repository Foundation and Quality Gates | Created in this planning task; awaiting user review | Not started | Not evaluated |
-| 2 — Guarded GitNexus Development Tooling | Intentionally deferred until Stage 1 completion; its future plan must define both paths, and Stage 2 execution records and evidences exactly one | Not started | Not evaluated |
-| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Intentionally deferred until Stage 1 and the Stage 2 governance outcome are complete; either outcome permits planning | Not started | Not evaluated |
+| 1 — Repository Foundation and Quality Gates | Approved and executed | Complete at `56d029e8e6d3c67dc6309b267c74833a09d2e419` | Complete |
+| 2 — Guarded GitNexus Development Tooling | Approved and executed | `ENABLED`: exact package, local index, project MCP, exclusions, and bounded read-only tools verified | Complete; ordinary offline verification also passes with GitNexus disabled |
+| 3 — Canonical Domain, Configuration, Hashing, and Schemas | Eligible for just-in-time planning after the completed Stage 2 governance decision | Not started | Not evaluated |
```

Do not change stage ordering, graph edges, or any gate.

- [ ] **Step 6: Define the enabled terminal record without writing it early**

This content is prohibited for 1.6.9. On an enabled candidate, retain the
following exact terminal content in this reviewed plan but do not create
`tools/gitnexus/outcome.json` until every A-J gate in Step 9 has passed:

```json
{
  "schema_version": 1,
  "stage": "project-1-stage-2",
  "outcome": "ENABLED",
  "stage_3_planning_permitted": true,
  "decision_date": "2026-08-11",
  "package_name": "gitnexus",
  "package_version": "1.6.9",
  "reason_codes": [],
  "required_mcp_controls": {
    "GITNEXUS_MCP_READ_ONLY": true,
    "GITNEXUS_MCP_ALLOWED_REPOS": true,
    "GITNEXUS_MCP_DEFAULT_REPO": true,
    "GITNEXUS_MCP_DEFAULT_MAX_TOKENS": true,
    "server_side_seven_tool_allowlist": true
  },
  "project_state": {
    "package_installed": true,
    "codex_mcp_configured": true,
    "index_present": true,
    "partial_configuration_present": false
  },
  "acceptance": {
    "bounded_local_query_succeeded": true,
    "license_compatible_for_personal_noncommercial_use": true,
    "manual_fallback_documented": true,
    "native_runtime_compatible": true,
    "ordinary_verification_without_gitnexus": true
  }
}
```

Task 1 proves the 1.6.9 gate is false, so execution of this plan must never
write this content. A different version requires a revised plan with different
exact identity rather than editing this record ad hoc. An enabled candidate
remains non-terminal while Steps 7 and 9 run.

- [ ] **Step 7: Turn the documentation/evidence test green**

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
uv run --no-sync ruff check tests/safety/test_gitnexus_development_tooling.py
uv run --no-sync mypy tests/safety/test_gitnexus_development_tooling.py
git diff --check
```

Expected: every command exits `0` with no outcome-based skip. For the selected
route, the tools directory contains exactly three inert files, Hatch config
excludes `/tools`, enabled-only paths remain absent, and documentation points
to the manual fallback. A conditional candidate instead proves its complete
enabled file set with no premature terminal `outcome.json`.

- [ ] **Step 7A: Commit outcome-neutral Task 7 files before candidate restarts**

This checkpoint is prohibited for the selected 1.6.9 disabled route. On
`ENABLED_CANDIDATE`, the exact static test and operator-documentation changes
from Steps 1-4 must be committed before A-J so each restart can require a clean
worktree without hiding or discarding reviewed work:

```powershell
$candidateDocumentationPaths = @(
    "AGENTS.md",
    "README.md",
    "tests/safety/test_gitnexus_development_tooling.py",
    "tools/gitnexus/README.md"
)
git add -- $candidateDocumentationPaths
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
git diff --cached --check
git diff --cached
git commit -m "docs: document optional gitnexus workflow"
git status --short
```

Expected: the commit is non-empty and contains exactly the four listed paths;
the roadmap is still baseline, `outcome.json` is still absent, the ledger route
remains `ENABLED_CANDIDATE`, and status is clean. Independently review this
checkpoint before continuing. Any failure routes through Task 4 Step 8 and the
later terminal commit includes the reviewed cleanup without rewriting history.

- [ ] **Step 8: Prove optionality for the selected disabled route**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
if (Test-Path -LiteralPath ".gitnexus") {
    throw "Disabled acceptance found a local index"
}
if (Test-Path -LiteralPath ".codex\config.toml") {
    throw "Disabled acceptance found an MCP entry"
}
$allowedEvidenceFiles = @(
    "README.md",
    "outcome.json",
    "supply-chain.json"
)
$actualEvidenceFiles = @(
    Get-ChildItem -LiteralPath "tools\gitnexus" -File -Recurse |
        ForEach-Object {
            $_.FullName.Substring(
                (Resolve-Path -LiteralPath "tools\gitnexus").Path.Length + 1
            ).Replace("\", "/")
        } |
        Sort-Object
)
if (Compare-Object $allowedEvidenceFiles $actualEvidenceFiles) {
    throw "Disabled evidence directory contains an executable or partial file"
}
```

Expected: the complete ordinary verifier exits `0` while package, Node tooling,
MCP, and index are absent; the three inert evidence files are the entire tools
directory. This proves `DISABLED_WITH_EVIDENCE` preserves normal development.

- [ ] **Step 9: On an enabled route, prove the complete A-J optionality matrix**

This step is prohibited for 1.6.9. On a gate-complete route, execute every
letter below in order and record every native exit in the ignored ledger.

**A. Verify the ordinary project with MCP disabled.** Apply this exact
temporary patch to `.codex/config.toml` with `apply_patch`:

```diff
-enabled = true
+enabled = false
```

Confirm the diff contains only that line, then record the exact restart boundary
before asking the user to close all ChatGPT Desktop windows:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.resume_task = 7
$ledger.resume_step = "9A_AFTER_DISABLED_RESTART"
$ledger.repository_status = "DIRTY_EXPECTED"
$ledger.pre_restart_commit = (git rev-parse HEAD).Trim()
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_A_DISABLED_RESTART_REQUIRED" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

After the user reopens this worktree, rehydrate and verify that boundary, prove
the host is disabled, restore the committed configuration without restarting
the host, and only then run the complete ordinary verifier:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$branch = (git branch --show-current).Trim()
$head = (git rev-parse HEAD).Trim()
if ($ledger.boundary -ne "OPTIONALITY_A_DISABLED_RESTART_REQUIRED" -or
    $ledger.resume_step -ne "9A_AFTER_DISABLED_RESTART" -or
    $branch -ne $ledger.branch -or
    $head -ne $ledger.pre_restart_commit) {
    throw "Optionality letter A restart state does not match its checkpoint"
}
git diff -- .codex/config.toml
codex mcp list
```

Apply the exact reverse `enabled = false` to `enabled = true` patch, then run:

```powershell
git diff --exit-code -- .codex/config.toml
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.resume_step = "9B"
$ledger.repository_status = "CLEAN"
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_A_COMPLETE" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: every command exits `0`; the running host remains disabled while the
committed `enabled = true` text is already restored, so all eight ordinary
offline operations and the exact static configuration test pass without
GitNexus participation. The persisted ledger prevents replay of letter A.

**B. Rehydrate and rebuild only from reviewed local state.** Run:

```powershell
pnpm.cmd --dir .\tools\gitnexus install --frozen-lockfile --offline --ignore-scripts
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 analyze
```

Expected: both commands exit `0`; no network or lifecycle script runs, the
reviewed lock is unchanged, and only the ignored disposable index is rebuilt.

**C. Run every deterministic static tooling test.** Run:

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
uv run --no-sync ruff check tests/safety/test_gitnexus_development_tooling.py
uv run --no-sync mypy tests/safety/test_gitnexus_development_tooling.py
```

Expected: every command exits `0` without a skip and without starting
GitNexus.

**D. Repeat the exact local CLI profiles.** Run:

```powershell
$wrapper = ".\tools\gitnexus\scripts\gitnexus.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper version
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper doctor
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper status
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper query
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper context
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper impact
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper trace
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper detect-changes
powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper check
```

Expected: every command exits `0`, uses only the fixed reviewed arguments, and
returns advisory results for `crypto-trading-lab`.

**E. Initialize the already-restored enabled MCP entry.** Require
`git diff --exit-code -- .codex/config.toml` to exit `0`, then persist the next
restart boundary:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$status = @(git status --short)
if ($status.Count -ne 0) {
    throw "Letter E requires a clean worktree before restart"
}
$ledger.resume_task = 7
$ledger.resume_step = "9F_AFTER_ENABLED_RESTART"
$ledger.repository_status = "CLEAN"
$ledger.pre_restart_commit = (git rev-parse HEAD).Trim()
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_E_ENABLED_RESTART_REQUIRED" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Ask the user to close every ChatGPT Desktop window and reopen this worktree.
Resume at letter F; do not replay letters A-D. This restart is the first point
after letter A at which the host may load the restored `enabled = true` value.

**F. Prove exact tool discovery.** Rehydrate the exact boundary first:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$status = @(git status --short)
$branch = (git branch --show-current).Trim()
$head = (git rev-parse HEAD).Trim()
if ($status.Count -ne 0 -or
    $ledger.boundary -ne "OPTIONALITY_E_ENABLED_RESTART_REQUIRED" -or
    $ledger.resume_step -ne "9F_AFTER_ENABLED_RESTART" -or
    $branch -ne $ledger.branch -or
    $head -ne $ledger.pre_restart_commit) {
    throw "Optionality letter F restart state does not match its checkpoint"
}
codex mcp list
```

Then inspect `/mcp` in ChatGPT Desktop. Both inspections must show one healthy,
non-required server named `gitnexus` and exactly this ordered tool set, with no
additional tool:
`list_repos`, `query`, `context`, `impact`, `trace`, `detect_changes`, `check`.

**G. Repeat every bounded MCP smoke.** Invoke the seven tools in that order
using exactly the seven JSON objects in Task 6 Step 8. Each call must return
without mutation, cross-repository data, a write approval, or an unbounded
result. Save only non-sensitive exit/result summaries in the ignored ledger.

**H. Disable without deleting configuration and verify again.** Apply the
same exact `enabled = true` to `enabled = false` patch from letter A, then write
the disabled-host restart boundary:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.resume_task = 7
$ledger.resume_step = "9H_AFTER_DISABLED_RESTART"
$ledger.repository_status = "DIRTY_EXPECTED"
$ledger.pre_restart_commit = (git rev-parse HEAD).Trim()
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_H_DISABLED_RESTART_REQUIRED" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Restart ChatGPT Desktop. After returning, rehydrate the checkpoint, confirm
`codex mcp list` reports the server disabled, apply the reverse patch to restore
`enabled = true` without restarting the host, and run:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$branch = (git branch --show-current).Trim()
$head = (git rev-parse HEAD).Trim()
if ($ledger.boundary -ne "OPTIONALITY_H_DISABLED_RESTART_REQUIRED" -or
    $ledger.resume_step -ne "9H_AFTER_DISABLED_RESTART" -or
    $branch -ne $ledger.branch -or
    $head -ne $ledger.pre_restart_commit) {
    throw "Optionality letter H disabled restart does not match its checkpoint"
}
codex mcp list
git diff --exit-code -- .codex/config.toml
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.resume_step = "9I"
$ledger.repository_status = "CLEAN"
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_H_COMPLETE" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: exit `0`; all eight ordinary checks pass while the running host is
disabled and the committed configuration text has already been restored. Do not
restart the host yet. Keeping the non-required MCP child stopped prevents it
from holding the disposable database open during letter I; the next enabled
restart is checkpointed after letter J.

**I. Remove the disposable index without affecting ordinary verification.**
Run this exact bounded move-and-restore block:

```powershell
$repositoryRoot = (git rev-parse --show-toplevel).Trim()
$indexSource = (Resolve-Path -LiteralPath ".gitnexus").Path
$repositoryPrefix = $repositoryRoot.TrimEnd("\") + "\"
if (-not $indexSource.StartsWith(
    $repositoryPrefix,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Index source is outside the worktree"
}
$temporaryRoot = [System.IO.Path]::GetTempPath()
$temporaryDirectory = Join-Path -Path $temporaryRoot -ChildPath (
    "crypto-trading-lab-gitnexus-" + [System.Guid]::NewGuid().ToString("N")
)
$null = New-Item -ItemType Directory -Path $temporaryDirectory
$temporaryResolved = (Resolve-Path -LiteralPath $temporaryDirectory).Path
if ($temporaryResolved.StartsWith(
    $repositoryPrefix,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Temporary destination is inside the worktree"
}
$movedIndex = Join-Path -Path $temporaryResolved -ChildPath ".gitnexus"
try {
    Move-Item -LiteralPath $indexSource -Destination $movedIndex
    if (Test-Path -LiteralPath ".gitnexus") {
        throw "Index was not removed from the worktree"
    }
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
    if ($LASTEXITCODE -ne 0) {
        throw "Ordinary verification failed without the index"
    }
}
finally {
    if ((Test-Path -LiteralPath $movedIndex) -and
        -not (Test-Path -LiteralPath ".gitnexus")) {
        Move-Item -LiteralPath $movedIndex -Destination ".gitnexus"
    }
    if ((Test-Path -LiteralPath $temporaryResolved) -and
        -not (Get-ChildItem -LiteralPath $temporaryResolved -Force)) {
        Remove-Item -LiteralPath $temporaryResolved -Force
    }
}
```

Expected: the verifier exits `0`; the index is absent only during the check,
is restored in `finally`, and the validated unique empty temporary directory
is removed without a recursive broad delete.

**J. Refresh the restored index and prove queries recover.** Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 analyze
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 query
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1 -RequireIndex
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
git status --short
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$status = @(git status --short)
if ($status.Count -ne 0) {
    throw "Letter J requires a clean worktree before the enabled restart"
}
$ledger.resume_task = 7
$ledger.resume_step = "9J_AFTER_ENABLED_RESTART"
$ledger.repository_status = "CLEAN"
$ledger.pre_restart_commit = (git rev-parse HEAD).Trim()
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_J_ENABLED_RESTART_REQUIRED" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: every command exits `0`; no network is used; the bounded advisory
query works again; `.codex/config.toml` is enabled and byte-for-byte committed;
the temporary move was restored; status is clean; and the ledger records the
only safe enabled-host restart after the database move test. Ask the user to
restart ChatGPT Desktop and return to this worktree. Then rehydrate the exact
checkpoint:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$status = @(git status --short)
$branch = (git branch --show-current).Trim()
$head = (git rev-parse HEAD).Trim()
if ($status.Count -ne 0 -or
    $ledger.boundary -ne "OPTIONALITY_J_ENABLED_RESTART_REQUIRED" -or
    $ledger.resume_step -ne "9J_AFTER_ENABLED_RESTART" -or
    $branch -ne $ledger.branch -or
    $head -ne $ledger.pre_restart_commit) {
    throw "Optionality letter J restart state does not match its checkpoint"
}
codex mcp list
```

Inspect `/mcp` and repeat the exact seven bounded Task 6 Step 8 calls. Require
the same exact non-required seven-tool surface with no write request, mutation,
cross-repository result, or unbounded response. Then close the boundary:

```powershell
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$ledger.resume_step = 10
$ledger | Add-Member -NotePropertyName boundary `
    -NotePropertyValue "OPTIONALITY_J_COMPLETE" -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Any failure routes through Task 4 Step 8's exact safe cleanup and terminal
disabled-evidence procedure.

- [ ] **Step 10: Finalize ENABLED only after A-J succeeds**

This step is prohibited for 1.6.9 and is skipped on the selected disabled
route. On a gate-complete candidate, create `tools/gitnexus/outcome.json` with
the exact Step 6 content and apply the complete exact enabled roadmap patch
from Step 5, then run:

```powershell
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
uv run --no-sync ruff check tests/safety/test_gitnexus_development_tooling.py
uv run --no-sync mypy tests/safety/test_gitnexus_development_tooling.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git diff --check
```

Expected: every command exits `0`; `_execution_route` is now terminal
`ENABLED`, the evidence-directory test requires the exact terminal file, every
A-J result remains recorded in ignored SDD evidence, and ordinary verification
remains independent. This is the first point at which `ENABLED` may be written.

- [ ] **Step 11: Review the full Stage 2 diff and safety boundary**

```powershell
$stage2BaseCommit = (git merge-base HEAD main).Trim()
if ([string]::IsNullOrWhiteSpace($stage2BaseCommit)) {
    throw "Unable to determine the Stage 2 base commit"
}
git diff --name-status "$stage2BaseCommit..HEAD"
git diff --stat "$stage2BaseCommit..HEAD"
git diff --check "$stage2BaseCommit..HEAD"
git diff "$stage2BaseCommit..HEAD"
git status --short
```

Before the Task 7 commit, append the working-tree diff for the five Task 7
paths. Expected for the disabled route: the complete path set is exactly
`.gitignore`, `AGENTS.md`, `README.md`, the roadmap, the Stage 2 safety test,
and the three inert tools evidence files. No source, Python dependency,
`uv.lock`, package manifest, pnpm lock, script, MCP file, GitNexus config,
index, runtime, credential, or engine file appears.

- [ ] **Step 12: Commit the final outcome documentation**

```powershell
$terminalStagePaths = @(
    ".gitignore",
    "AGENTS.md",
    "README.md",
    "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md",
    "tests/safety/test_gitnexus_development_tooling.py",
    "tools/gitnexus"
)
git add -A -- $terminalStagePaths
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$conditionalRootPaths = @(
    ".gitnexusrc",
    ".gitnexusignore",
    ".codex/config.toml"
)
foreach ($conditionalPath in $conditionalRootPaths) {
    $trackedMatch = @(git ls-files -- $conditionalPath)
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    if ($trackedMatch.Count -ne 0 -or
        (Test-Path -LiteralPath $conditionalPath)) {
        git add -A -- $conditionalPath
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
}
git diff --cached --check
git diff --cached
git commit -m "docs: record gitnexus governance outcome"
```

Expected for the disabled route: the commit contains the five changed paths
(`outcome.json` is already identical and therefore is not staged as a change).
For an enabled route, the same command also commits the final outcome change.
After any candidate failure, the same bounded staging logic also includes every
tracked enabled-only deletion and the disabled outcome; no Task 7 documentation
or safety-test change is left unstaged.

- [ ] **Step 13: Run final branch acceptance fresh**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
$stage2BaseCommit = (git merge-base HEAD main).Trim()
$stage2FeatureHead = (git rev-parse HEAD).Trim()
if ([string]::IsNullOrWhiteSpace($stage2BaseCommit) -or
    [string]::IsNullOrWhiteSpace($stage2FeatureHead)) {
    throw "Unable to record the reviewed Stage 2 range"
}
git diff --check "$stage2BaseCommit..HEAD"
git diff --name-status "$stage2BaseCommit..HEAD"
git diff "$stage2BaseCommit..HEAD"
git status --short
git branch --show-current
$stage2FeatureHead
```

Expected: all commands exit `0`; tests have no outcome-based skips; the full
diff is reviewed; status is clean; branch is
`project-1-stage-2-gitnexus-tooling`; and the feature HEAD is recorded as
`stage2FeatureHead`.

Persist the merge-ready checkpoint exactly:

```powershell
$ledgerPath = ".superpowers/sdd/stage-2-gitnexus/state.json"
$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
$terminalOutcome = Get-Content -LiteralPath "tools/gitnexus/outcome.json" -Raw |
    ConvertFrom-Json
$ledger.completed_tasks = @(1, 2, 3, 4, 5, 6, 7)
$ledger.resume_task = $null
$ledger.resume_step = $null
$ledger.repository_status = "CLEAN"
$ledger.terminal_outcome = $terminalOutcome.outcome
$ledger | Add-Member -NotePropertyName feature_head `
    -NotePropertyValue $stage2FeatureHead -Force
$ledger | Add-Member -NotePropertyName merge_ready `
    -NotePropertyValue $true -Force
$ledgerJson = $ledger | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $ledgerPath),
    $ledgerJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

- [ ] **Step 14: Fast-forward directly into local main after final review**

From the main checkout, run:

```powershell
$featureBranch = "project-1-stage-2-gitnexus-tooling"
$reviewedFeatureHead = (
    Read-Host "Enter the exact feature HEAD approved by the Task 7 reviewer"
).Trim()
if ($reviewedFeatureHead -notmatch '^[0-9a-fA-F]{40}$') {
    throw "The reviewed feature HEAD is not a full commit SHA"
}
$status = @(git status --short)
$mainBranch = (git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
    throw "Local main must be clean before integration"
}
if ($mainBranch -ne "main") {
    throw "Integration checkout is not on main"
}
$stage2BaseCommit = (git merge-base main $featureBranch).Trim()
$stage2FeatureHead = (git rev-parse $featureBranch).Trim()
$mainHead = (git rev-parse HEAD).Trim()
if ([string]::IsNullOrWhiteSpace($stage2BaseCommit) -or
    [string]::IsNullOrWhiteSpace($stage2FeatureHead)) {
    throw "Unable to rehydrate the reviewed Stage 2 range"
}
if ($stage2FeatureHead -ne $reviewedFeatureHead) {
    throw "Feature branch HEAD differs from the independently reviewed commit"
}
if ($mainHead -ne $stage2BaseCommit) {
    throw "Local main changed after the Stage 2 worktree was created"
}
git merge --ff-only $featureBranch
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$mergedHead = (git rev-parse HEAD).Trim()
if ($mergedHead -ne $reviewedFeatureHead) {
    throw "Fast-forward main does not equal the reviewed feature HEAD"
}
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git merge-base --is-ancestor $stage2FeatureHead main
git status --short
git log -8 --oneline
```

Expected: initial main is clean and on `main`; the branch head exactly equals
the full SHA independently recorded in Step 13; the merge is fast-forward-only;
no merge commit is created; merged main equals that reviewed SHA; the complete
ordinary verifier passes again; final status is clean. Do not fetch, pull,
push, create a pull request, rebase, squash, amend, or delete the external
worktree/feature branch.

If `tools/gitnexus/outcome.json` records `ENABLED`, continue before claiming
merged-main acceptance:

```powershell
$outcome = Get-Content -LiteralPath "tools/gitnexus/outcome.json" -Raw |
    ConvertFrom-Json
if ($outcome.outcome -ne "ENABLED") {
    throw "Merged-main rehydration is only for the enabled outcome"
}
pnpm.cmd --dir .\tools\gitnexus install --frozen-lockfile --offline --ignore-scripts
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\gitnexus.ps1 analyze
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1 -RequireIndex
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
$mainRestartLedger = ".superpowers/sdd/stage-2-gitnexus/main-restart.json"
$mainRestartRoot = Split-Path -Parent $mainRestartLedger
New-Item -ItemType Directory -Path $mainRestartRoot -Force | Out-Null
$mainRestartCheckpoint = [ordered]@{
    schema_version = 1
    branch = "main"
    commit = (git rev-parse HEAD).Trim()
    outcome = "ENABLED"
    boundary = "MERGED_MAIN_CHATGPT_DESKTOP_RESTART_REQUIRED"
    resume_task = 7
    resume_step = 15
}
$mainRestartJson = $mainRestartCheckpoint | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $mainRestartLedger),
    $mainRestartJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: every command exits `0`; main recreates only ignored `node_modules`
and `.gitnexus/` from committed local state, both verifiers pass, and the
ignored ledger contains no path, credential, or environment value. Ask the
user to trust this main checkout through the normal Codex host UI if needed,
without committing a `[projects.<absolute-path>]` entry; then close all
ChatGPT Desktop windows, reopen the main checkout, and resume at Step 15.

- [ ] **Step 15: Complete enabled merged-main MCP acceptance after restart**

This step is not run for `DISABLED_WITH_EVIDENCE`. For `ENABLED`, run:

```powershell
$mainRestartLedger = ".superpowers/sdd/stage-2-gitnexus/main-restart.json"
$resume = Get-Content -LiteralPath $mainRestartLedger -Raw | ConvertFrom-Json
$status = @(git status --short)
$branch = (git branch --show-current).Trim()
$head = (git rev-parse HEAD).Trim()
if ($status.Count -ne 0 -or $branch -ne "main" -or $head -ne $resume.commit) {
    throw "Merged main does not match its restart checkpoint"
}
codex mcp list
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\gitnexus\scripts\verify.ps1 -RequireIndex
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git status --short
```

Inspect `/mcp` and repeat the exact seven Task 6 Step 8 calls against main.
Expected: the non-required server is healthy, only the seven approved tools
are exposed, every bounded call is repository-confined and non-mutating, both
verifiers exit `0`, and status is clean. After every call and check succeeds,
close the restart boundary explicitly:

```powershell
$mainRestartLedger = ".superpowers/sdd/stage-2-gitnexus/main-restart.json"
$resume = Get-Content -LiteralPath $mainRestartLedger -Raw | ConvertFrom-Json
if ($resume.boundary -ne "MERGED_MAIN_CHATGPT_DESKTOP_RESTART_REQUIRED" -or
    $resume.resume_task -ne 7 -or
    $resume.resume_step -ne 15) {
    throw "Merged-main restart checkpoint is not the expected open boundary"
}
$resume.boundary = "MERGED_MAIN_MCP_ACCEPTANCE_COMPLETE"
$resume.resume_task = $null
$resume.resume_step = $null
$mainRestartJson = $resume | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $mainRestartLedger),
    $mainRestartJson,
    [System.Text.UTF8Encoding]::new($false)
)
```

Expected: the ignored restart record is terminal and cannot cause Task 7 or
MCP smoke calls to replay. If this conditional acceptance fails, Stage 2 is
not complete. Execute Task 4 Step 8's exact MCP-disable, bounded
removal, bounded deletion-staging, and disabled-outcome construction blocks,
but do not run its feature-worktree roadmap-transition or `state.json`
continuation blocks. Then run this exact merged-main reconciliation:

```powershell
$roadmapPath = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
$enabledRow = '| 2 — Guarded GitNexus Development Tooling | Approved and executed | `ENABLED`: exact package, local index, project MCP, exclusions, and bounded read-only tools verified | Complete; ordinary offline verification also passes with GitNexus disabled |'
$disabledRow = '| 2 — Guarded GitNexus Development Tooling | Approved and executed | `DISABLED_WITH_EVIDENCE`: pinned 1.6.9 lacks mandatory MCP controls; no partial tooling remains | Complete; ordinary offline verification and manual fallback recorded |'
$roadmapAbsolutePath = Join-Path -Path (Get-Location).Path -ChildPath $roadmapPath
$roadmap = [System.IO.File]::ReadAllText(
    $roadmapAbsolutePath,
    [System.Text.UTF8Encoding]::new($false)
)
if (-not $roadmap.Contains($enabledRow)) {
    throw "Merged-main rollback cannot find the ENABLED roadmap row"
}
$disabledRoadmap = $roadmap.Replace($enabledRow, $disabledRow)
[System.IO.File]::WriteAllText(
    $roadmapAbsolutePath,
    $disabledRoadmap,
    [System.Text.UTF8Encoding]::new($false)
)
$mainRestartLedger = ".superpowers/sdd/stage-2-gitnexus/main-restart.json"
$resume = Get-Content -LiteralPath $mainRestartLedger -Raw | ConvertFrom-Json
$resume.outcome = "DISABLED_WITH_EVIDENCE"
$resume.boundary = "DISABLED_AFTER_MERGED_MAIN_MCP_FAILURE"
$resume.resume_task = $null
$resume.resume_step = $null
$mainRestartJson = $resume | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path -Path (Get-Location).Path -ChildPath $mainRestartLedger),
    $mainRestartJson,
    [System.Text.UTF8Encoding]::new($false)
)
uv run --no-sync pytest -o addopts="" tests/safety/test_gitnexus_development_tooling.py -q
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
$correctionPaths = @(
    ".gitnexusrc",
    ".gitnexusignore",
    ".codex/config.toml",
    "tools/gitnexus",
    $roadmapPath
)
git add -A -- $correctionPaths
git diff --cached --check
git diff --cached
git commit -m "chore: disable unsafe gitnexus integration"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
git status --short
```

Expected: every command exits `0`; the terminal outcome, roadmap, enabled-only
deletions, and ignored restart ledger all say disabled; static and ordinary
verification pass; and the non-empty correction commit preserves history.
Never rewrite or force-update an earlier commit.

**Focused verification:** Final outcome test, exact evidence directory,
documentation links, roadmap status, disabled absence or enabled A-J matrix.

**Broader verification:** Complete ordinary verifier on the feature branch and
merged main, full base-to-HEAD diff, security review, independent review, and
clean status.

**Security review:** Confirm no credential/environment value, private path,
runtime data, package executable, unignored index, product dependency,
application network behavior, or authority inversion entered the branch.

**Commit:** Exact Task 7 command and message are in Step 12. Correction commits
are allowed only for non-empty independently reviewed defects. Use TDD for
production behavior, include every correction in the base-to-HEAD review, and
never create an empty verification commit.

**Independent review gate:** A fresh reviewer validates the final outcome,
exact file set, fallback, optionality evidence, full diff, all verification
exits, and merge readiness before Step 14.

## Outcome-specific acceptance

### `ENABLED`

All of the following must be true together:

- Exact package version, license, repository, integrity, Node/native behavior,
  package-manager lock, and lifecycle allowlist are verified.
- The executable is project-local and every invocation uses a committed
  wrapper; there is no PATH/global fallback.
- The server itself implements all four ADR controls and the seven-tool
  restriction; client filtering is additional defense only.
- `.gitnexusrc`, `.gitnexusignore`, `.gitignore`, and protected-source hashes
  prove index-only operation, no generated instructions/skills, no embeddings,
  and no sensitive/runtime indexing.
- Project Codex MCP is non-required, has exact timeouts, exact tools, four and
  only four environment controls, deterministic root behavior, and no private
  path or secret.
- CLI and MCP bounded calls pass; host restart resumes at the recorded boundary.
- The full A-J optionality matrix and ordinary offline verifier pass.

Failure of one item means the outcome is not enabled.

### `DISABLED_WITH_EVIDENCE`

All of the following must be true together:

- `tools/gitnexus/supply-chain.json` records exact inspected identity and
  official sources; `outcome.json` records deterministic reason codes.
- The evidence directory contains only its README and two JSON records.
- No package manifest, pnpm workspace/lock, install, wrapper, `node_modules`,
  `.gitnexusrc`, `.gitnexusignore`, `.codex/config.toml`, or `.gitnexus/` exists.
- No project-local GitNexus process or partial MCP state remains.
- Manual source, reference, and diff analysis is documented.
- The unchanged complete ordinary verifier passes offline without GitNexus.
- The outcome is recorded in repository instructions and roadmap status.

This outcome completes Stage 2 and permits Stage 3 planning.

## Plan self-review checklist

Before accepting Stage 2 execution, verify each statement against fresh files
and command evidence:

1. ADR 0001 is implemented completely without changing the approved
   architecture, scope, authority order, or master-roadmap stage order.
2. The plan matches the actual Stage 1 files, 112-test baseline, complete
   ordinary verifier, empty Python runtime dependencies, and Hatch file map.
3. Exact package `gitnexus` 1.6.9, SHA-512 integrity, SHA-1, repository tag and
   directory, license, publication date, and binary mapping are recorded from
   primary sources.
4. Actual Node 25.9.0, npm 11.9.0, pnpm 11.9.0, absent Corepack, and untrusted
   pre-existing launcher facts are recorded without private paths.
5. The conditional route chooses exactly project-local pnpm 11.9.0, with its
   exact v11 `strictDepBuilds`/`allowBuilds` policy and generated frozen lock.
6. No moving `@latest` package tag or other floating GitNexus version is used.
7. No global installation, PATH/global launcher dependency, npx, pnpx, dlx,
   Corepack installation, or Corepack package-manager use is proposed; the only
   Corepack invocation is Task 1's read-only availability probe.
8. No `gitnexus setup` execution or generated GitNexus setup automation exists.
9. No plugin, hook, generated skill, wiki, web UI, serve, publish, group,
   rename, raw-Cypher, embedding, remote-model, or unallowlisted-tool
   enablement exists.
10. `scripts/verify.ps1` is unchanged and independent of GitNexus, Node, npm,
    pnpm, MCP, `node_modules`, and the local index.
11. `ENABLED` and `DISABLED_WITH_EVIDENCE` are both exact terminal outcomes;
    1.6.9 deterministically selects the latter.
12. Both outcomes complete Stage 2, record
    `stage_3_planning_permitted = true`, and permit Stage 3 planning.
13. Restart continuation records exact completed tasks, resume point, commit,
    branch, candidate route, and clean status without a private path.
14. Direct integration is local fast-forward only, with no remote operation,
    pull request, rebase, squash, amend, merge commit, or worktree deletion.
15. Every planned text file has complete exact content or an exact patch; the
    generated pnpm lock has one offline construction and integrity-validation
    procedure and is never hand-edited.
16. No banned drafting marker, unresolved technology choice, deferred command
    shape, or ambiguous outcome transition remains.
17. No credential, username, private absolute path, ambient environment value,
    package-manager authentication material, or secret-bearing field is
    embedded.
18. During this planning task only this Stage 2 plan file changed; execution
    later changes only its exact outcome-specific file map and no application
    source, engine, Python dependency, `uv.lock`, runtime, schema, migration,
    database, trading, network-client, or Stage 3 feature.

## Execution handoff

- Obtain user approval of this plan before Stage 2 execution.
- Use `superpowers:subagent-driven-development` with a fresh worker and
  independent review for each task, or `superpowers:executing-plans` if the
  user explicitly selects inline execution.
- Create the isolated external worktree only at execution time.
- For the researched exact pin, follow `DISABLED_WITH_EVIDENCE`; do not request
  installation approval, invoke GitNexus, create an index, or configure MCP.
- After the branch and merged main both pass fresh verification, Stage 2 is
  complete and Stage 3 planning may begin in a separate approved task.
- Retain the external worktree and feature branch until the user explicitly
  approves removal.
