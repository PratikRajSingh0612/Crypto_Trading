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

import pytest

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
_EXPECTED_TERMINAL_OUTCOME_KEYS = {
    "schema_version",
    "stage",
    "outcome",
    "stage_3_planning_permitted",
    "decision_date",
    "package_name",
    "package_version",
    "reason_codes",
    "required_mcp_controls",
    "project_state",
    "fallback",
}
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
_FORBIDDEN_SECRET_FIELDS = {
    "api_key",
    "apikey",
    "password",
    "credential",
    "auth_token",
    "access_token",
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
        assert set(outcome) == _EXPECTED_TERMINAL_OUTCOME_KEYS
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


def _contains_forbidden_secret_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_SECRET_FIELDS:
                return True
            if _contains_forbidden_secret_field(nested_value):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_secret_field(item) for item in value)
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

    assert project["dependencies"] == [
        "alembic>=1.13,<2",
        "pydantic>=2.12,<3",
        "pyyaml>=6.0.3,<7",
        "sqlalchemy>=2.0,<3",
    ]
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


def test_tooling_evidence_directory_matches_outcome(repository_root: Path) -> None:
    route = _execution_route(repository_root)
    prefix = "tools/gitnexus/"
    relative_files = {
        path.removeprefix(prefix)
        for path in _tracked_paths(repository_root)
        if path.startswith(prefix)
    }
    enabled_files = {
        "README.md",
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "scripts/gitnexus-mcp.ps1",
        "scripts/gitnexus.ps1",
        "scripts/install.ps1",
        "scripts/verify.ps1",
        "supply-chain.json",
    }

    if route == "DISABLED_WITH_EVIDENCE":
        assert relative_files == {
            "README.md",
            "outcome.json",
            "supply-chain.json",
        }
    elif route == "ENABLED_CANDIDATE":
        assert relative_files == enabled_files
        assert _terminal_outcome(repository_root) is None
    else:
        assert route == "ENABLED"
        assert relative_files == enabled_files | {"outcome.json"}

    pyproject = _load_toml(repository_root / "pyproject.toml")
    hatch = cast(dict[str, Any], pyproject["tool"])["hatch"]
    build = cast(dict[str, Any], hatch["build"])
    targets = cast(dict[str, Any], build["targets"])
    sdist = cast(dict[str, Any], targets["sdist"])
    include = cast(list[str], sdist["include"])
    assert all(path != "/tools" and not path.startswith("/tools/") for path in include)
    wheel = cast(dict[str, Any], targets["wheel"])
    assert wheel["packages"] == ["src/crypto_lab"]


def test_terminal_outcome_matches_roadmap_status(repository_root: Path) -> None:
    route = _execution_route(repository_root)
    roadmap = (
        repository_root
        / "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
    ).read_text(encoding="utf-8")
    assert "Stages 1 through 7 have approved detailed implementation plans." in roadmap
    assert "Only Stage 1 has a detailed implementation plan" not in roadmap
    approved_stage_2_plan = (
        "**Approved detailed implementation plan:** "
        "`docs/superpowers/plans/"
        "2026-08-10-project-1-gitnexus-development-tooling-implementation-plan.md`."
    )
    obsolete_stage_2_plan = (
        "**Planned detailed implementation plan:** "
        "`docs/superpowers/plans/"
        "2026-08-10-project-1-gitnexus-development-tooling-implementation-plan.md`."
    )
    assert approved_stage_2_plan in roadmap
    assert obsolete_stage_2_plan not in roadmap
    enabled_row = (
        "| 2 — Guarded GitNexus Development Tooling | Approved and executed | "
        "`ENABLED`: exact package, local index, project MCP, exclusions, and "
        "bounded read-only tools verified | Complete; ordinary offline "
        "verification also passes with GitNexus disabled |"
    )
    disabled_row = (
        "| 2 — Guarded GitNexus Development Tooling | Approved and executed | "
        "`DISABLED_WITH_EVIDENCE`: pinned 1.6.9 lacks mandatory MCP controls; "
        "no partial tooling remains | Complete; ordinary offline verification "
        "and manual fallback recorded |"
    )
    if route == "ENABLED_CANDIDATE":
        assert enabled_row not in roadmap
        assert disabled_row not in roadmap
        return

    assert (
        "**Status:** Approved planning decomposition; Stages 1 through 7 complete"
        in roadmap
    )
    if route == "ENABLED":
        assert enabled_row in roadmap
        assert disabled_row not in roadmap
    else:
        assert route == "DISABLED_WITH_EVIDENCE"
        assert disabled_row in roadmap
        assert enabled_row not in roadmap


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
    assert not _contains_forbidden_secret_field(manifest)
    assert outcome is None or not _contains_forbidden_secret_field(outcome)
    texts = [json.dumps(manifest, sort_keys=True)]
    if outcome is not None:
        texts.append(json.dumps(outcome, sort_keys=True))
    for relative_path in _ENABLED_ONLY_PATHS:
        path = repository_root / relative_path
        if path.exists():
            texts.append(path.read_text(encoding="utf-8"))
    combined = "\n".join(texts)

    for forbidden_field in _FORBIDDEN_SECRET_FIELDS:
        assert (
            re.search(
                rf"(?im)^\s*[\"']?{forbidden_field}[\"']?\s*[:=]",
                combined,
            )
            is None
        )
    assert re.search(r"[a-z]:\\users\\[^<]", combined, re.IGNORECASE) is None


def test_unknown_outcome_keys_are_rejected(
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = _terminal_outcome(repository_root)
    assert outcome is not None
    tainted_outcome = {**outcome, "unexpected_review_key": True}

    def _tainted_terminal_outcome(_: Path) -> dict[str, Any] | None:
        return tainted_outcome

    monkeypatch.setitem(globals(), "_terminal_outcome", _tainted_terminal_outcome)
    with pytest.raises(AssertionError):
        _execution_route(repository_root)


def test_later_nested_secret_like_keys_are_rejected(
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(repository_root)
    tainted_manifest = {
        **manifest,
        "review_probe": {"safe": True, "api_key": "sentinel"},
    }

    def _tainted_manifest(_: Path) -> dict[str, Any]:
        return tainted_manifest

    monkeypatch.setitem(globals(), "_manifest", _tainted_manifest)
    with pytest.raises(AssertionError):
        test_manifest_and_config_contain_no_secret_fields(repository_root)
