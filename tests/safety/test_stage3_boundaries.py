"""Enforce the Stage 3 architectural, source, schema, and verifier boundary."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from crypto_lab.schema_registry import SCHEMA_DEFINITIONS

_ALLOWED_SOURCE_FILES = {
    "__init__.py",
    "adapters/__init__.py",
    "adapters/descriptors.py",
    "adapters/versioning.py",
    "artifacts/__init__.py",
    "artifacts/ownership.py",
    "audit/__init__.py",
    "capabilities/__init__.py",
    "cli/__init__.py",
    "cli/__main__.py",
    "cli/main.py",
    "configuration/__init__.py",
    "configuration/loader.py",
    "configuration/models.py",
    "configuration/snapshot.py",
    "datasets/__init__.py",
    "datasets/hashing.py",
    "datasets/models.py",
    "domain/__init__.py",
    "domain/base.py",
    "domain/canonical_json.py",
    "domain/capability_names.py",
    "domain/capability_requirements.py",
    "domain/comparison_levels.py",
    "domain/diagnostics.py",
    "domain/financial.py",
    "domain/hashing.py",
    "domain/identifiers.py",
    "domain/records.py",
    "domain/results.py",
    "domain/time.py",
    "domain/versioning.py",
    "experiments/__init__.py",
    "persistence/__init__.py",
    "process_supervision/__init__.py",
    "schema_registry.py",
    "strategy/__init__.py",
    "strategy/evaluation.py",
    "strategy/expressions.py",
    "strategy/feature_graph.py",
    "strategy/loader.py",
    "strategy/models.py",
    "strategy/validation.py",
    "strategy/versioning.py",
    "strategy/yaml_source.py",
}
_ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "codecs",
    "collections",
    "contextlib",
    "copy",
    "crypto_lab",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "hashlib",
    "importlib",
    "json",
    "pathlib",
    "pydantic",
    "re",
    "tomllib",
    "types",
    "typing",
    "uuid",
    "yaml",
}
# `types` is the narrowest root in the set. Plan section 5.5.1's deep-immutability
# landing needs exactly one name from it, in exactly one file, so the root alone
# is not a sufficient guard: `test_the_types_root_is_confined_to_one_exact_import`
# pins the location and the form as well.
_TYPES_ROOT = "types"
_TYPES_IMPORTER = "strategy/models.py"
_TYPES_SYMBOL = "MappingProxyType"
_FORBIDDEN_PATH_ACCESS = {
    "pathlib.Path.cwd",
    "pathlib.Path.expanduser",
    "pathlib.Path.home",
}
_PROHIBITED_OS_ATTRIBUTES = frozenset({"getenv", "environ", "putenv", "unsetenv"})
_PROHIBITED_CONTROL_LITERAL = "PYDANTIC_DISABLE_PLUGINS"
_DEFERRED_DEFINITIONS = {
    "AdapterCatalog",
    "AdapterCatalogEntry",
    "AdapterCommand",
    "AdapterCommandRequestEnvelope",
    "AdapterResultManifest",
    "AdapterValidationResult",
    "ApproximationDeclaration",
    "ArtifactFinalizationPurpose",
    "ArtifactFinalizer",
    "ArtifactOwnerKind",
    "ArtifactRef",
    "ArtifactRepository",
    "ArtifactSourceRole",
    "AuditSink",
    "AuditEvent",
    "BootstrapDescriptorEnvelope",
    "CancellationToken",
    "CandidateArtifact",
    "CandidateArtifactRepository",
    "CandidateArtifactState",
    "CandidateArtifactProducerKind",
    "CandidateFinalization",
    "CanonicalFill",
    "CanonicalOrder",
    "CapabilityDeclaration",
    "CapabilityVocabulary",
    "CommandInvocationRecord",
    "CommandInvocationRepository",
    "CommandInvocationState",
    "CommandKind",
    "CommandResult",
    "ComparisonEligibilityResult",
    "ComparisonEligibilityService",
    "CompatibilityPolicy",
    "CompatibilityResolver",
    "CompatibilityOutcome",
    "CompatibilityResult",
    "ContentHasher",
    "Clock",
    "DatasetRepository",
    "EngineRunRecord",
    "EngineRunRepository",
    "EngineRunRequest",
    "EquityPoint",
    "EvidenceFinalizationRequest",
    "ExperimentRecord",
    "ExperimentRepository",
    "ExperimentSpec",
    "Fee",
    "FinalizationResult",
    "NegotiationResult",
    "MetricValue",
    "MonotonicInstant",
    "OrderSide",
    "OrderType",
    "PortfolioSnapshot",
    "PositionSnapshot",
    "PositionEffect",
    "ProcessSupervisor",
    "ProtocolEventEnvelope",
    "ResultFinalizationRequest",
    "RetryPolicy",
    "Result",
    "RunEvent",
    "RunManifest",
    "RuntimeAvailabilityObservation",
    "SanitizedAdapterResultManifest",
    "SemanticStatus",
    "UnitOfWork",
    "ValidationOutcome",
    "ingest_dataset",
    "negotiate_protocol",
    "normalize_dataset",
    "place_order",
}
_EXPECTED_VERIFICATION_PROFILES = (
    ("lock-check",),
    ("sync",),
    ("ruff-format-all",),
    ("ruff-check-all",),
    ("mypy-all",),
    ("schema-generate-check",),
    ("pytest-all",),
    ("build",),
    ("schema-distribution",),
)
_EXPECTED_VERIFIER_SHA256 = (
    "4296811ae310fc7e8e17bd3b63f4c6c794a2c6e3c8d20b642de40cf918c2c4cd"
)
_ALLOWED_VERIFIER_COMMANDS = {
    "Assert-NativeSuccess",
    "Join-Path",
    "Pop-Location",
    "Push-Location",
    "Resolve-Path",
    "Write-Host",
    "git",
    "powershell",
}


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return None if parent is None else f"{parent}.{node.attr}"
    return None


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.partition(".")[0]
                aliases[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                aliases[bound] = f"{node.module}.{alias.name}"
    return aliases


def _resolved_qualified_name(
    node: ast.AST,
    aliases: dict[str, str],
) -> str | None:
    name = _qualified_name(node)
    if name is None:
        return None
    head, separator, tail = name.partition(".")
    resolved = aliases.get(head, head)
    return resolved if not separator else f"{resolved}.{tail}"


def _os_aliases(tree: ast.AST) -> frozenset[str]:
    aliases: set[str] = {"os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    aliases.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            aliases.add("os")
    return frozenset(aliases)


def _environment_access_violations(
    tree: ast.AST,
    relative_path: str,
) -> list[str]:
    violations: list[str] = []
    os_aliases = _os_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name in _PROHIBITED_OS_ATTRIBUTES:
                    violations.append(
                        f"{relative_path}:{node.lineno}: "
                        f"prohibited from os import {alias.name}"
                    )
        if isinstance(node, ast.Attribute) and node.attr in _PROHIBITED_OS_ATTRIBUTES:
            base = _qualified_name(node.value)
            if base in os_aliases:
                violations.append(
                    f"{relative_path}:{node.lineno}: prohibited os.{node.attr}"
                )
        if isinstance(node, ast.Call) and _qualified_name(node.func) == "getattr":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                attr = node.args[1].value
                if isinstance(attr, str) and attr in _PROHIBITED_OS_ATTRIBUTES:
                    base = _qualified_name(node.args[0])
                    if base in os_aliases:
                        violations.append(
                            f"{relative_path}:{node.lineno}: "
                            f"prohibited getattr os access {attr}"
                        )
        if isinstance(node, ast.Constant) and node.value == _PROHIBITED_CONTROL_LITERAL:
            violations.append(
                f"{relative_path}:{node.lineno}: prohibited control literal"
            )
    return violations


def _source_files(repository_root: Path) -> tuple[Path, ...]:
    return tuple(sorted((repository_root / "src/crypto_lab").rglob("*.py")))


def _normalized_source(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line.rstrip() for line in lines) + "\n"


def _powershell() -> str:
    executable = shutil.which("powershell")
    assert executable is not None
    return executable


def _powershell_command_records(
    path: Path,
    repository_root: Path,
) -> tuple[dict[str, str], ...]:
    parser = (
        "$path=[Console]::In.ReadLine();$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$path,[ref]$tokens,[ref]$errors);"
        "if($errors.Count-ne 0){exit 91};"
        "$records=@($ast.FindAll({param($node) $node -is "
        "[System.Management.Automation.Language.CommandAst]},$true)|"
        "ForEach-Object{$name=$_.GetCommandName();"
        "if($null-eq$name){$name='<dynamic>'};"
        "[pscustomobject]@{name=$name;text=$_.Extent.Text}});"
        "$records|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(  # noqa: S603 - reviewed fixed parser boundary
        [_powershell(), "-NoProfile", "-Command", parser],
        cwd=repository_root,
        input=f"{path}\n",
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    decoded = json.loads(completed.stdout)
    records = [decoded] if isinstance(decoded, dict) else decoded
    assert isinstance(records, list)
    assert all(isinstance(record, dict) for record in records)
    return tuple(records)


def _normalized_extent(text: str) -> str:
    return " ".join(text.replace("`", "").split())


def _verifier_profiles(
    records: tuple[dict[str, str], ...],
) -> tuple[tuple[str, ...], ...]:
    profiles: list[tuple[str, ...]] = []
    for record in records:
        if record["name"].casefold() != "powershell":
            continue
        tokens = _normalized_extent(record["text"]).split()
        launcher_index = next(
            index
            for index, token in enumerate(tokens)
            if token.casefold().endswith("scripts\\invoke-uv.ps1")
        )
        profiles.append(tuple(tokens[launcher_index + 1 :]))
    return tuple(profiles)


def _verifier_is_exactly_closed(path: Path, repository_root: Path) -> bool:
    digest = hashlib.sha256(_normalized_source(path).encode()).hexdigest()
    records = _powershell_command_records(path, repository_root)
    commands = {record["name"] for record in records}
    return (
        digest == _EXPECTED_VERIFIER_SHA256
        and commands == _ALLOWED_VERIFIER_COMMANDS
        and _verifier_profiles(records) == _EXPECTED_VERIFICATION_PROFILES
        and tuple(
            _normalized_extent(record["text"])
            for record in records
            if record["name"].casefold() == "git"
        )
        == ("& git diff --check",)
    )


def test_stage3_source_file_set_is_closed(repository_root: Path) -> None:
    source = repository_root / "src/crypto_lab"
    actual = {
        path.relative_to(source).as_posix() for path in _source_files(repository_root)
    }
    assert actual == _ALLOWED_SOURCE_FILES


def test_source_imports_only_the_explicit_stage3_allowlist(
    repository_root: Path,
) -> None:
    failures: list[str] = []
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                modules.append(node.module)
            for module in modules:
                root = module.partition(".")[0]
                if root not in _ALLOWED_IMPORT_ROOTS:
                    failures.append(f"{path}: import root is not allowed: {module}")
    assert failures == []


def test_the_import_root_allowlist_is_exactly_the_reviewed_twenty_two() -> None:
    """An exact set, not a lower bound: a silent addition must fail here.

    The count is asserted alongside the set so the reviewed number 22 appears
    literally, which is what plan section 3.9 and Appendix C pin.
    """
    assert len(_ALLOWED_IMPORT_ROOTS) == 22
    assert _ALLOWED_IMPORT_ROOTS == {
        "__future__",
        "argparse",
        "codecs",
        "collections",
        "contextlib",
        "copy",
        "crypto_lab",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "hashlib",
        "importlib",
        "json",
        "pathlib",
        "pydantic",
        "re",
        "tomllib",
        "types",
        "typing",
        "uuid",
        "yaml",
    }


def test_the_types_root_is_confined_to_one_exact_import(
    repository_root: Path,
) -> None:
    """`types` is allowlisted only for `from types import MappingProxyType`.

    Plan section 5.5.1 authorizes the root for one name in one file, so the root
    membership above is deliberately not the whole guard. This fails when the
    root is imported from a second source file, when a bare `import types`
    replaces the exact form, when an alias is used, when a second symbol joins
    the statement, and when the symbol is dropped while the root stays
    allowlisted.
    """
    source_root = repository_root / "src/crypto_lab"
    observed: list[tuple[str, int]] = []
    failures: list[str] = []

    for path in _source_files(repository_root):
        relative = path.relative_to(source_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.partition(".")[0] == _TYPES_ROOT:
                        failures.append(
                            f"{relative}:{node.lineno}: "
                            f"`import {alias.name}` is not the approved form"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                if node.module.partition(".")[0] != _TYPES_ROOT:
                    continue
                if relative != _TYPES_IMPORTER:
                    failures.append(
                        f"{relative}:{node.lineno}: only {_TYPES_IMPORTER} "
                        f"may import the {_TYPES_ROOT} root"
                    )
                    continue
                if node.module != _TYPES_ROOT:
                    failures.append(
                        f"{relative}:{node.lineno}: submodule import "
                        f"`{node.module}` is not approved"
                    )
                    continue
                names = [alias.name for alias in node.names]
                if names != [_TYPES_SYMBOL]:
                    failures.append(
                        f"{relative}:{node.lineno}: expected exactly "
                        f"[{_TYPES_SYMBOL}], found {names}"
                    )
                    continue
                if node.names[0].asname is not None:
                    failures.append(
                        f"{relative}:{node.lineno}: {_TYPES_SYMBOL} must not be aliased"
                    )
                    continue
                observed.append((relative, node.lineno))

    assert failures == []
    # The root is allowlisted *because* this import exists. If the
    # implementation stops needing it, the root must leave the set in the same
    # change, so an unused permission cannot linger.
    assert [relative for relative, _ in observed] == [_TYPES_IMPORTER]


def test_project_source_has_no_environment_access(
    repository_root: Path,
) -> None:
    source_root = repository_root / "src/crypto_lab"
    failures: list[str] = []
    for path in _source_files(repository_root):
        relative = path.relative_to(source_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        failures.extend(_environment_access_violations(tree, relative))
    assert failures == []


def test_source_has_no_path_ambient_access_or_later_stage_definitions(
    repository_root: Path,
) -> None:
    failures: list[str] = []
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = _import_aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name | ast.Attribute):
                name = _resolved_qualified_name(node, aliases)
                if name in _FORBIDDEN_PATH_ACCESS:
                    failures.append(f"{path}: forbidden path access {name}")
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                if node.name in _DEFERRED_DEFINITIONS:
                    failures.append(f"{path}: later-stage definition {node.name}")
    assert failures == []


def test_environment_scan_detects_aliased_os_access() -> None:
    tree = ast.parse(
        "import os as operating\n"
        "operating.getenv('name')\n"
        "getattr(operating, 'environ')\n"
    )
    violations = _environment_access_violations(tree, "probe.py")
    assert any("getenv" in item for item in violations)
    assert any("environ" in item for item in violations)


def test_environment_scan_detects_from_os_import() -> None:
    tree = ast.parse("from os import putenv\n")
    violations = _environment_access_violations(tree, "probe.py")
    assert any("putenv" in item for item in violations)


def test_environment_scan_detects_control_literal() -> None:
    tree = ast.parse('control = "PYDANTIC_DISABLE_PLUGINS"\n')
    violations = _environment_access_violations(tree, "probe.py")
    assert violations == ["probe.py:1: prohibited control literal"]


@pytest.mark.parametrize("name", sorted(_DEFERRED_DEFINITIONS))
def test_each_normative_deferred_symbol_is_detected_by_the_stage3_guard(
    name: str,
) -> None:
    keyword = "class" if name[0].isupper() else "def"
    tree = ast.parse(
        f"{keyword} {name}:\n    pass\n"
        if keyword == "class"
        else f"def {name}():\n    pass\n"
    )
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert defined & _DEFERRED_DEFINITIONS == {name}


@pytest.mark.parametrize(
    "name",
    [
        "AdapterResultManifest",
        "CandidateArtifactState",
        "CanonicalOrder",
        "CommandInvocationState",
        "EngineRunRequest",
        "PortfolioSnapshot",
        "ValidationOutcome",
    ],
)
def test_representative_later_stage_type_mutations_are_blocked(name: str) -> None:
    tree = ast.parse(f"class {name}:\n    pass\n")
    later = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name in _DEFERRED_DEFINITIONS
    }
    assert later == {name}


def test_schema_registry_is_closed_and_protocol_descriptors_are_located_correctly() -> (
    None
):
    paths = tuple(
        definition.relative_path.as_posix() for definition in SCHEMA_DEFINITIONS
    )
    identifiers = tuple(definition.schema_id for definition in SCHEMA_DEFINITIONS)
    assert len(paths) == 11
    assert len(paths) == len(set(paths))
    assert len(identifiers) == len(set(identifiers))
    assert "protocol/engine-descriptor-v1.schema.json" in paths
    assert "protocol/adapter-descriptor-v1.schema.json" in paths
    assert all(not path.startswith("adapters/") for path in paths)
    assert all("semantic-version" not in path for path in paths)


def test_schema_tool_import_path_is_pytest_only_and_not_runtime_packaged(
    repository_root: Path,
) -> None:
    project = tomllib.loads(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    pytest_options = project["tool"]["pytest"]["ini_options"]
    assert pytest_options["pythonpath"] == ["scripts"]
    wheel = project["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["packages"] == ["src/crypto_lab"]
    assert wheel["dev-mode-dirs"] == ["src"]
    assert wheel["force-include"] == {"schemas": "crypto_lab/schemas"}
    assert not (repository_root / "scripts" / "__init__.py").exists()


def test_complete_verifier_has_exact_offline_order(repository_root: Path) -> None:
    verifier = repository_root / "scripts" / "verify.ps1"
    assert _verifier_is_exactly_closed(verifier, repository_root)


@pytest.mark.parametrize(
    ("injected", "expected_ast_name"),
    [
        (
            "bitsadmin /transfer bad https://example.invalid out",
            "bitsadmin",
        ),
        (
            "certutil -urlcache -split -f https://example.invalid out",
            "certutil",
        ),
        ("[System.Net.Http.HttpClient]::new()", None),
        ("$executable = 'uv'; & $executable --version", "<dynamic>"),
    ],
)
def test_verifier_mutations_fail_exact_hash_and_ast_closure(
    repository_root: Path,
    tmp_path: Path,
    injected: str,
    expected_ast_name: str | None,
) -> None:
    source = _normalized_source(repository_root / "scripts" / "verify.ps1")
    mutated = tmp_path / "mutated-verifier.ps1"
    mutated.write_text(f"{source}{injected}\n", encoding="utf-8")
    assert not _verifier_is_exactly_closed(mutated, repository_root)
    if expected_ast_name is not None:
        records = _powershell_command_records(mutated, repository_root)
        assert expected_ast_name in {record["name"] for record in records}


def test_readme_uses_only_closed_stage3_launcher_setup(
    repository_root: Path,
) -> None:
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    _, heading, remainder = readme.partition("## Local setup\n")
    assert heading == "## Local setup\n"
    local_setup, next_heading, _ = remainder.partition(
        "\n## Explicit configuration and schemas"
    )
    assert next_heading == "\n## Explicit configuration and schemas"
    preamble, fence, command_tail = local_setup.partition("```powershell\n")
    assert preamble == "\nFrom the repository root:\n\n"
    assert fence == "```powershell\n"
    commands, fence, prose = command_tail.partition("\n```\n")
    assert fence == "\n```\n"
    assert commands.splitlines() == [
        "uv --version",
        "uv python find --managed-python --system --no-python-downloads 3.12",
        "powershell -NoProfile -ExecutionPolicy Bypass -File "
        r".\scripts\invoke-uv.ps1 sync",
        "powershell -NoProfile -ExecutionPolicy Bypass -File "
        r".\scripts\invoke-uv.ps1 cli-version",
        "powershell -NoProfile -ExecutionPolicy Bypass -File "
        r".\scripts\invoke-uv.ps1 cli-module-version",
    ]
    assert prose == (
        "\nThe first two commands are read-only prerequisite checks. `--system` "
        "skips the\n"
        "project `.venv` during discovery, `--managed-python` still requires a\n"
        "uv-managed install, and `--no-python-downloads` makes a missing managed\n"
        "interpreter fail instead of acquiring one. The discovery command does "
        "not\n"
        "modify system Python. `.python-version` requests Python 3.12,\n"
        '`python-preference = "only-managed"` prevents system-Python fallback, '
        "and\n"
        '`python-downloads = "manual"` disables automatic interpreter downloads.\n'
        "\n"
        "Normal project execution uses `.venv` only through the "
        "repository-controlled\n"
        "`scripts/invoke-uv.ps1` child launcher. Both launcher version profiles "
        "print\n"
        "`crypto-lab 0.1.0`. Ordinary development and verification remain "
        "offline.\n"
        "Always run the launcher `sync` profile first. If its cache is "
        "incomplete, stop.\n"
        "Only the exact Stage 3 Task 1 `sync-acquire` launcher profile may "
        "acquire the\n"
        "missing distributions, and only after separate explicit one-time "
        "approval.\n"
        "After that acquisition succeeds, rerun the launcher `sync` profile.\n"
    )
    assert "\nuv sync " not in readme
    assert "\nuv run " not in readme
    assert "Task 2 bootstrap" not in readme


def test_gitnexus_remains_disabled_with_evidence(repository_root: Path) -> None:
    outcome = (repository_root / "tools/gitnexus/outcome.json").read_text(
        encoding="utf-8"
    )
    assert '"outcome": "DISABLED_WITH_EVIDENCE"' in outcome


STAGE3_TASK8_COMMIT = "d50744547d121d1b5925a5d92d752345902f5e56"
STAGE3_IMPLEMENTATION_COMMIT = "88711307ff377e645bb17c798e599b6bac1c2be4"
STAGE3_STABILITY_CORRECTION_COMMIT = "e1c821453459f5eccf86a472e9204b6a90829d64"
STAGE4_LAUNCHER_BOOTSTRAP_COMMIT = "350fac49ff5b1db4ec62b60c7ade76580f9894dd"
STAGE4_PLAN_APPROVAL_COMMIT = "b6721b870c79db7b999b9eb70107e53992cbe1ab"
STAGE4_PLAN = (
    "docs/superpowers/plans/2026-08-10-project-1-portable-strategy-"
    "capabilities-comparison-implementation-plan.md"
)


def test_stage3_completion_status_is_exact(repository_root: Path) -> None:
    for commit in (
        STAGE3_TASK8_COMMIT,
        STAGE3_IMPLEMENTATION_COMMIT,
        STAGE3_STABILITY_CORRECTION_COMMIT,
    ):
        assert re.fullmatch(r"[0-9a-f]{40}", commit) is not None
    assert len({STAGE3_IMPLEMENTATION_COMMIT, STAGE3_STABILITY_CORRECTION_COMMIT}) == 2
    roadmap = (
        repository_root
        / "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
    ).read_text(encoding="utf-8")
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    assert "Stages 1 through 3 complete" in roadmap
    assert "Stages 1 through 3 have approved detailed implementation plans." in roadmap
    assert (
        "**Approved detailed implementation plan:** "
        "`docs/superpowers/plans/"
        "2026-08-10-project-1-canonical-domain-configuration-hashing-schemas-"
        "implementation-plan.md`."
    ) in roadmap
    assert (
        "**Planned detailed implementation plan:** "
        "`docs/superpowers/plans/"
        "2026-08-10-project-1-canonical-domain-configuration-hashing-schemas-"
        "implementation-plan.md`."
    ) not in roadmap
    assert (
        "| Dependency bootstrap network | Run launcher profiles "
        "`lock-resolve-offline`, `lock-check`, and `sync` first; only the exact "
        "Stage 3 Task 1 `lock-acquire` and `sync-acquire` profiles may omit "
        "offline after separate one-time approval; the historical Stage 1 "
        "exceptions grant no Stage 3 authority; verification never uses the "
        "network |"
    ) in roadmap
    assert (
        "| Dependency bootstrap network | Offline resolution, lock check, and "
        "synchronization first; only the exact one-time Task 1 `uv lock` and "
        "`uv sync --frozen --no-install-project` fallbacks may run after "
        "separate user approval when required metadata or locked distributions "
        "are absent; verification never uses the network |"
    ) not in roadmap
    assert (
        "| 3 — Canonical Domain, Configuration, Hashing, and Schemas | "
        "Approved and executed | Implementation complete at "
        f"`{STAGE3_IMPLEMENTATION_COMMIT}`; post-completion stability "
        f"correction merged at `{STAGE3_STABILITY_CORRECTION_COMMIT}` | "
        "Complete; canonical models, explicit configuration, named hashes, "
        "dataset metadata, structural descriptors, artifact owners, and 11 "
        "generated schemas verified offline |"
    ) in roadmap
    assert f"Complete at `{STAGE3_TASK8_COMMIT}`" not in roadmap
    assert "Eligible for just-in-time planning after Stage 3 completion" in roadmap
    assert "`DISABLED_WITH_EVIDENCE`" in roadmap
    assert "**Status:** Project 1 Stages 1-3 complete" in readme


def test_stage4_plan_approval_status_is_exact(repository_root: Path) -> None:
    for commit in (STAGE4_LAUNCHER_BOOTSTRAP_COMMIT, STAGE4_PLAN_APPROVAL_COMMIT):
        assert re.fullmatch(r"[0-9a-f]{40}", commit) is not None
    assert len({STAGE4_LAUNCHER_BOOTSTRAP_COMMIT, STAGE4_PLAN_APPROVAL_COMMIT}) == 2
    roadmap = (
        repository_root
        / "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
    ).read_text(encoding="utf-8")
    plan = (repository_root / STAGE4_PLAN).read_text(encoding="utf-8")

    assert "**Status:** Approved for Project 1 Stage 4 implementation" in plan
    assert (
        "**Execution prerequisites, both of which must be ancestors of local "
        "`main`\nbefore Stage 4 implementation begins:** the launcher bootstrap "
        f"correction at\n`{STAGE4_LAUNCHER_BOOTSTRAP_COMMIT}`"
    ) in plan

    approved_line = f"**Approved detailed implementation plan:** `{STAGE4_PLAN}`."
    planned_line = f"**Planned detailed implementation plan:** `{STAGE4_PLAN}`."
    assert approved_line in roadmap
    assert planned_line not in roadmap
    assert (
        "| 4 — Portable Strategy, Capabilities, and Comparison | Eligible for "
        "just-in-time planning after Stage 3 completion; corrected detailed "
        f"plan approved at `{STAGE4_PLAN_APPROVAL_COMMIT}` after two "
        "independent reviews, superseding the pre-correction review at "
        "`bf5e427a8fe055be2b6cb803b69d4c2334aeee69`; launcher bootstrap "
        f"prerequisite completed at `{STAGE4_LAUNCHER_BOOTSTRAP_COMMIT}` | "
        "Not started | Not evaluated |"
    ) in roadmap

    # Stage 4 implementation has not started, and Stage 5 has not started.
    assert "Stages 1 through 3 complete" in roadmap
    assert (
        "| 5 — Experiment, Run, Invocation, Retry, and Aggregation Logic | "
        "Intentionally deferred until Stages 3\u20134 completion | Not started | "
        "Not evaluated |"
    ) in roadmap
