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
    "adapters/catalog.py",
    "adapters/commands.py",
    "adapters/descriptors.py",
    "adapters/diagnostics.py",
    "adapters/envelopes.py",
    "adapters/events.py",
    "adapters/exit_codes.py",
    "adapters/limits.py",
    "adapters/manifests.py",
    "adapters/negotiation.py",
    "adapters/paths.py",
    "adapters/ports.py",
    "adapters/reconciliation.py",
    "adapters/sanitization.py",
    "adapters/versioning.py",
    "adapters/vocabulary.py",
    "artifacts/__init__.py",
    "artifacts/ownership.py",
    "audit/__init__.py",
    "capabilities/__init__.py",
    "capabilities/comparison.py",
    "capabilities/models.py",
    "capabilities/policy.py",
    "capabilities/resolver.py",
    "capabilities/vocabulary.py",
    "cli/__init__.py",
    "cli/__main__.py",
    "cli/main.py",
    "configuration/__init__.py",
    "configuration/loader.py",
    "configuration/models.py",
    "configuration/retry_policy.py",
    "configuration/snapshot.py",
    "datasets/__init__.py",
    "datasets/hashing.py",
    "datasets/models.py",
    "domain/__init__.py",
    "domain/aggregation.py",
    "domain/base.py",
    "domain/canonical_json.py",
    "domain/capability_names.py",
    "domain/capability_requirements.py",
    "domain/command_invocation.py",
    "domain/comparison_levels.py",
    "domain/compatibility.py",
    "domain/descriptors.py",
    "domain/diagnostics.py",
    "domain/engine_run.py",
    "domain/experiment.py",
    "domain/financial.py",
    "domain/hashing.py",
    "domain/identifiers.py",
    "domain/lifecycle.py",
    "domain/ports.py",
    "domain/records.py",
    "domain/results.py",
    "domain/retry.py",
    "domain/time.py",
    "domain/versioning.py",
    "experiments/__init__.py",
    "experiments/aggregation.py",
    "experiments/diagnostics.py",
    "experiments/experiment_service.py",
    "experiments/invocation_service.py",
    "experiments/ports.py",
    "experiments/requests.py",
    "experiments/retry.py",
    "experiments/run_service.py",
    "experiments/semantic_outcome.py",
    "experiments/supervision_lifecycle.py",
    "persistence/__init__.py",
    "persistence/database.py",
    "persistence/diagnostics.py",
    "persistence/migration_runner.py",
    "persistence/migrations/__init__.py",
    "persistence/migrations/env.py",
    "persistence/migrations/versions/__init__.py",
    "persistence/migrations/versions/r0001_stage8_baseline.py",
    "persistence/schema.py",
    "process_supervision/__init__.py",
    "process_supervision/cancellation.py",
    "process_supervision/deadlines.py",
    "process_supervision/diagnostics.py",
    "process_supervision/models.py",
    "process_supervision/ports.py",
    "process_supervision/readers.py",
    "process_supervision/reconciliation.py",
    "process_supervision/roots.py",
    "process_supervision/supervisor.py",
    "process_supervision/windows_api.py",
    "process_supervision/windows_process.py",
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
    "alembic",
    "argparse",
    "asyncio",
    "codecs",
    "collections",
    "contextlib",
    "copy",
    "crypto_lab",
    "ctypes",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "hashlib",
    "importlib",
    "json",
    "pathlib",
    "pydantic",
    "queue",
    "re",
    "sqlalchemy",
    "subprocess",
    "threading",
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
#: Specification section 5.1 forbids these two roots inside the strategy and
#: capabilities packages. Both are in ``_ALLOWED_IMPORT_ROOTS`` because
#: ``configuration``, ``cli``, and ``schema_registry`` need them, so nothing
#: else in the repository narrows them per package.
_PACKAGES_DENIED_FILESYSTEM_AND_DYNAMIC_IMPORT = frozenset({"capabilities", "strategy"})
_ROOTS_DENIED_IN_THOSE_PACKAGES = frozenset({"importlib", "pathlib"})
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
    "ArtifactFinalizationPurpose",
    "ArtifactFinalizer",
    "ArtifactOwnerKind",
    "ArtifactRef",
    "ArtifactRepository",
    "ArtifactSourceRole",
    "AuditSink",
    "AuditEvent",
    "CandidateArtifact",
    "CandidateArtifactRepository",
    "CandidateArtifactState",
    "CandidateArtifactProducerKind",
    "CandidateFinalization",
    "CanonicalFill",
    "CanonicalOrder",
    "ComparisonEligibilityService",
    "ContentHasher",
    "DatasetRepository",
    "EquityPoint",
    "EvidenceFinalizationRequest",
    "Fee",
    "FinalizationResult",
    "MetricValue",
    "OrderSide",
    "OrderType",
    "PortfolioSnapshot",
    "PositionSnapshot",
    "PositionEffect",
    "ResultFinalizationRequest",
    "Result",
    "RunManifest",
    "ingest_dataset",
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
    ("migration-check",),
    ("pytest-all",),
    ("build",),
    ("schema-distribution",),
)
_EXPECTED_VERIFIER_SHA256 = (
    "ec818bc7551984878f2f4e57845ec7417b68839d889496acb3e43cb5c895ea7d"
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


def _imported_roots(tree: ast.AST) -> tuple[str, ...]:
    roots: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.append(node.module.partition(".")[0])
    return tuple(roots)


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

    The Stage 7 plan's section 2.6 adds five roots across Tasks 1, 3, 4 and 6,
    each in the commit that first imports it and each confined by the Stage 7
    guard to the modules that section names, so the pinned count reads
    twenty-two plus the roots added so far: Task 1 added `threading`
    (`process_supervision/cancellation.py`), giving 23; Task 3 added `queue`
    (`process_supervision/readers.py`), giving 24; Task 4 added `ctypes`
    (`process_supervision/windows_api.py`) and `subprocess`
    (`process_supervision/windows_process.py`), giving 26; Task 6 added
    `asyncio` (`process_supervision/supervisor.py`, imported function-locally
    inside `invoke`), giving 27.

    The Stage 8 plan's section 2.6 adds two roots across Tasks 1 and 2, each in
    the commit that first imports it and each confined by the Stage 8 guard to
    the persistence modules that section names, so the pinned count reads
    twenty-seven plus the roots added so far: Task 1 added `sqlalchemy`
    (`persistence/database.py`), giving 28; Task 2 added `alembic`
    (`persistence/migration_runner.py`, `persistence/migrations/env.py` and the
    baseline revision), giving 29. The test name is historical and is kept.
    """
    assert len(_ALLOWED_IMPORT_ROOTS) == 29
    assert _ALLOWED_IMPORT_ROOTS == {
        "__future__",
        "alembic",
        "argparse",
        "asyncio",
        "codecs",
        "collections",
        "contextlib",
        "copy",
        "crypto_lab",
        "ctypes",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "hashlib",
        "importlib",
        "json",
        "pathlib",
        "pydantic",
        "queue",
        "re",
        "sqlalchemy",
        "subprocess",
        "threading",
        "tomllib",
        "types",
        "typing",
        "uuid",
        "yaml",
    }


def test_strategy_and_capabilities_import_no_pathlib_or_importlib(
    repository_root: Path,
) -> None:
    """Specification section 5.1 prohibition, unguarded until Task 9.

    Both roots are in the 22-root allowlist because other packages need them,
    so nothing else in the repository would reject them here. Adding
    ``from pathlib import Path`` to the strategy loader would give it the
    filesystem reach section 5.1 exists to deny.
    """
    source = repository_root / "src/crypto_lab"
    failures: list[str] = []
    for path in _source_files(repository_root):
        relative = path.relative_to(source)
        if relative.parts[0] not in _PACKAGES_DENIED_FILESYSTEM_AND_DYNAMIC_IMPORT:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for root in _imported_roots(tree):
            if root in _ROOTS_DENIED_IN_THOSE_PACKAGES:
                failures.append(f"{relative.as_posix()}: forbidden import root: {root}")
    assert failures == []


@pytest.mark.parametrize(
    "source",
    [
        "import pathlib",
        "import importlib",
        "import pathlib as p",
        "import importlib.util",
        "from pathlib import Path",
        "from importlib.util import resolve_name",
    ],
)
def test_the_import_root_scanner_detects_each_forbidden_shape(source: str) -> None:
    """The prohibition guard begins green, so prove the scanner is load-bearing."""
    roots = _imported_roots(ast.parse(source))
    assert set(roots) & _ROOTS_DENIED_IN_THOSE_PACKAGES != set()


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


def test_the_deferred_definition_set_is_exactly_the_reviewed_sixty_five() -> None:
    """An exact set, not a lower bound: a silent removal must fail here.

    Without this, deleting a name deletes the parametrized case below that
    would have caught it, so the suite shrinks instead of failing. The count
    matches the plans' own arithmetic: the Stage 4 plan's section 3.9 records
    79 at Stage 3 and its section 9.8 removes exactly fourteen, giving the
    sixty-five this test is named for. The Stage 5 plan's section 2.7 then
    releases twelve names across Tasks 1 through 6, each in the task that
    first defines it, so the pinned count reads sixty-five minus the names
    released so far: Task 1 released `Clock`, `CommandKind` and
    `CommandInvocationState`, giving 62; Task 2 released `RetryPolicy`,
    `ExperimentSpec` and `ExperimentRecord`, giving 59; Task 3 released
    `CommandInvocationRecord`, giving 58; Task 4 released `EngineRunRecord`,
    giving 57; Task 6 released `ExperimentRepository`, `EngineRunRepository`,
    `UnitOfWork` and `CommandInvocationRepository`, giving 53.

    The Stage 6 plan's section 2.6 releases sixteen names across Tasks 1
    through 6, each in the task that first defines it, so the pinned count reads
    fifty-three minus the names released so far: Task 1 released
    `SemanticStatus`, `ValidationOutcome`, `AdapterCatalog` and
    `AdapterCatalogEntry`, giving 49; Task 2 released
    `AdapterCommandRequestEnvelope`, `EngineRunRequest` and `AdapterCommand`,
    giving 46; Task 3 released `BootstrapDescriptorEnvelope`,
    `NegotiationResult` and `negotiate_protocol`, giving 43; Task 4 released
    `ProtocolEventEnvelope` and `RunEvent`, giving 41; Task 5 released
    `AdapterValidationResult`, `AdapterResultManifest` and
    `SanitizedAdapterResultManifest`, giving 38; Task 6 released
    `CommandResult`, giving 37.

    The Stage 7 plan's section 2.6 releases three names across Tasks 1 and 2,
    each in the task that first defines it, so the pinned count reads
    thirty-seven minus the names released so far: Task 1 released
    `CancellationToken` (`domain/ports.py`) and `MonotonicInstant`
    (`domain/time.py`), giving 35; Task 2 released `ProcessSupervisor`
    (`process_supervision/ports.py`), giving 34.
    """
    assert len(_DEFERRED_DEFINITIONS) == 34
    assert _DEFERRED_DEFINITIONS == {
        "ArtifactFinalizationPurpose",
        "ArtifactFinalizer",
        "ArtifactOwnerKind",
        "ArtifactRef",
        "ArtifactRepository",
        "ArtifactSourceRole",
        "AuditSink",
        "AuditEvent",
        "CandidateArtifact",
        "CandidateArtifactRepository",
        "CandidateArtifactState",
        "CandidateArtifactProducerKind",
        "CandidateFinalization",
        "CanonicalFill",
        "CanonicalOrder",
        "ComparisonEligibilityService",
        "ContentHasher",
        "DatasetRepository",
        "EquityPoint",
        "EvidenceFinalizationRequest",
        "Fee",
        "FinalizationResult",
        "MetricValue",
        "OrderSide",
        "OrderType",
        "PortfolioSnapshot",
        "PositionSnapshot",
        "PositionEffect",
        "ResultFinalizationRequest",
        "Result",
        "RunManifest",
        "ingest_dataset",
        "normalize_dataset",
        "place_order",
    }


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
        # Stage 6 plan section 2.6: Task 5 released `AdapterResultManifest` and
        # swapped in a still-deferred name so seven live cases remain.
        "CandidateArtifact",
        "CandidateArtifactState",
        "CanonicalOrder",
        # Stage 6 plan section 2.6: Task 2 released `EngineRunRequest` and
        # swapped in a still-deferred name so seven live cases remain.
        "RunManifest",
        "PortfolioSnapshot",
        # Stage 6 plan section 2.6: Task 4 released `RunEvent` and swapped in a
        # still-deferred name so seven live cases remain.
        "ArtifactRef",
        # Stage 7 plan section 2.6: Task 2 released `ProcessSupervisor` (the name
        # Stage 6 Task 1 had swapped in for `ValidationOutcome`) and swapped in a
        # still-deferred name so seven live cases remain.
        "ArtifactFinalizer",
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
    # Stage 6 plan section 2.6: Task 9 appended the eight protocol entries.
    assert len(paths) == 35
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
STAGE4_IMPLEMENTATION_COMMIT = "33f5b1c3b644c1df7e8db0df17dae88c6bcea2ce"
#: Plan rule 1: every commit touching the Stage 4 plan file, in commit order.
#: Derived with `git log --reverse -- <STAGE4_PLAN>`, not transcribed from the
#: plan. Some entries also appear in the follow-up tuple below, because those
#: commits changed both the plan and the implementation.
STAGE4_PLAN_CORRECTION_COMMITS = (
    "65eca5b17d45c0cf04f856dc6049e0c3ee7a2be9",
    "f898499d647d1d4ade571345973c6ced5e84403c",
    "f57357379222404685d805d081de4f61f36a7fe5",
    "cfede94c5de22fba93176e4d5f75aceeffc7695e",
    "7830f935e069d0fb3053682095e949cedb4bb1de",
    "2edd529a93547b4374e65de78f21619f5122b498",
    "a5112b2812b5dccf5e4c12ec6d7b08a43232a65f",
    "f5de3305d71713c452bccc74823b4c1e016c1814",
    "77e0bc2e327bac333d228c6e4cde08c2cedf21a5",
)
#: Plan rule 2: the post-Task-8 implementation correction, then every review
#: follow-up in commit order. Recorded separately from the implementation hash,
#: exactly as the Stage 3 row separates its post-completion stability
#: correction.
STAGE4_EVALUATOR_CORRECTION_COMMIT = "7f7bfce12abc72a63b8624562ff2e448a26f7610"
STAGE4_REVIEW_FOLLOWUP_COMMITS = (
    "a5112b2812b5dccf5e4c12ec6d7b08a43232a65f",
    "f5de3305d71713c452bccc74823b4c1e016c1814",
    "77e0bc2e327bac333d228c6e4cde08c2cedf21a5",
)
STAGE4_ROADMAP = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
STAGE4_VERIFICATION_GUIDE = "docs/development/verification.md"
#: Interim phrasings that Task 9's own commit makes false. None may survive in
#: either documentation file.
_RETIRED_STATUS_PHRASES = (
    "awaits Task 9",
    "Task 9 pending",
)
_README_STAGE4_STATUS = (
    "Project 1 Stage 4 is complete. Portable strategy ingestion, "
    "deterministic Level 1 evaluation, strategy versioning and hashing, "
    "capability resolution, comparison eligibility, and the reviewed "
    "20-schema registry are implemented. Stage 4 implementation completed at "
    f"`{STAGE4_IMPLEMENTATION_COMMIT}`; the final status was recorded by the "
    "separate Task 9 status commit. Stage 5 has not started."
)
_VERIFICATION_STAGE4_STATUS = "\n".join(
    (
        "Project 1 Stage 4 is complete. Stage 4 implementation completed at",
        f"`{STAGE4_IMPLEMENTATION_COMMIT}`; the final status was recorded by",
        "the separate Task 9 status commit. The closed 20-schema registry holds",
        "the nine new Stage 4 schemas together with the eleven Stage 3 schemas,",
        "preserved byte-identical to `main`. Stage 5 is not started.",
    )
)
#: The claims the sweeps actually support. NOT "zero disagreement between the
#: published schemas and the runtime validators" -- the schema-workflow section
#: of the same file records forty-six under-rejections resolving to eleven
#: rules, which are exactly that kind of disagreement.
_VERIFICATION_CORPUS_QUALIFICATION = "\n".join(
    (
        "The independent sweeps agree on the falsifiable results: zero",
        "over-rejections, and zero disagreement between the four schema surfaces.",
        "The published bytes are therefore a superset of the runtime, never a",
        "subset. The two sweeps do not agree on the residual set of inexpressible",
        "rules, and that register is a maintained enumeration rather than a",
        "machine-verified closure, not a claim that every possible runtime or",
        "schema rule was exhaustively enumerated.",
    )
)
#: The non-goal exclusions, pinned verbatim so the completion wording cannot be
#: widened by deleting them.
_VERIFICATION_NON_GOALS = "\n".join(
    (
        "No real trading engine, exchange connectivity, market-data download, real",
        "backtest, order or fill simulation, portfolio accounting, persistence, paper",
        "wallet, tax or TDS logic, LLM integration, user interface, Docker "
        "setup, cloud",
        "deployment, or server deployment exists anywhere in the repository. Stage 4",
        "executes no engine, no adapter, no strategy, and no declared engine "
        "extension,",
        "and combines no comparison result into an averaged, voted, or synthetic "
        "figure.",
    )
)
_STAGE4_ROADMAP_STATUS_LINE = (
    "**Status:** Approved planning decomposition; Stages 1 through 4 complete"
)
_STAGE4_ROADMAP_PLAN_SENTENCE = (
    "Stages 1 through 4 have approved detailed implementation plans."
)
_STAGE4_ROADMAP_ROW = (
    "| 4 — Portable Strategy, Capabilities, and Comparison | Approved and "
    "executed; corrected detailed plan approved at "
    f"`{STAGE4_PLAN_APPROVAL_COMMIT}` after two independent reviews, "
    "superseding the pre-correction review at "
    "`bf5e427a8fe055be2b6cb803b69d4c2334aeee69`; launcher bootstrap "
    f"prerequisite completed at `{STAGE4_LAUNCHER_BOOTSTRAP_COMMIT}`; reviewed "
    "plan corrections at "
    + ", ".join(f"`{commit}`" for commit in STAGE4_PLAN_CORRECTION_COMMITS)
    + " | Implementation complete at "
    f"`{STAGE4_IMPLEMENTATION_COMMIT}`; post-completion evaluator "
    f"rendering-bound correction at `{STAGE4_EVALUATOR_CORRECTION_COMMIT}`, with "
    "review follow-ups at "
    + ", ".join(f"`{commit}`" for commit in STAGE4_REVIEW_FOLLOWUP_COMMITS)
    + "; final status recorded by the separate "
    "Task 9 status commit, which is a status record and not the implementation "
    "hash | Complete; portable strategy ingestion, static validation, "
    "deterministic Level 1 evaluation, strategy versioning and hashing, "
    "capability vocabulary and compatibility resolution, comparison "
    "eligibility, and the closed 20-schema registry — 9 new Stage 4 schemas "
    "with the 11 Stage 3 schemas preserved byte-identical — verified offline "
    "on the complete verifier, which passed on its first attempt; GitNexus "
    "remains `DISABLED_WITH_EVIDENCE` with the manual source, reference, and "
    # Stage 5 plan section 2.7: the one clause of this row Task 9 changes.
    "diff fallback recorded; Stage 5 complete |"
)
#: Section 11 item 3, byte-exact including its hard wrapping. Reverting item 3
#: to the symmetric "within one point" wording removes this sentence. No
#: negative pin accompanies it: the retired phrasing necessarily survives
#: inside item 3's own rationale for retiring it, so a whole-file negative pin
#: would be false the moment it was written.
_STAGE4_COVERAGE_SENTENCE = "\n".join(
    (
        "3. Branch coverage must be at least 90.00 percent and must not be more than",
        "   1.00 percentage point below the Stage 3 baseline of 93.64 percent. "
        "Coverage",
        "   above the Stage 3 baseline is permitted.",
    )
)

# --- Stage 5 Task 9: the completion-status successors of plan section 2.7 ---------
#
# The Stage 5 implementation hash is the Task 8 commit, the last commit that adds
# Stage 5 behaviour. Plan section 2.7 requires Task 9 to introduce this constant in
# the same commit that changes the prose and section 14.1 makes Task 9 one commit,
# so the constant cannot name the Task 9 commit itself (a commit cannot contain its
# own hash; the Stage 4 rule, roadmap Stage 4 row). Every surface that names the
# hash also says, in the same sentence, that the seven Stage 5 schemas, the closed
# 27-schema registry, the two Stage 5 guards, the in-memory flow and the status
# itself were added by the separate Task 9 commit, which is not the implementation
# hash; that commit's hash is reported in the completion report and the merge
# evidence, never written into its own tree.
STAGE5_IMPLEMENTATION_COMMIT = "71ab94d8e9e13d6895cef9346ed58a711c8819f3"
STAGE5_PLAN = (
    "docs/superpowers/plans/2026-08-10-project-1-experiment-run-invocation-retry-"
    "aggregation-implementation-plan.md"
)
_README_STAGE5_STATUS = (
    "Project 1 Stage 5 is complete. Experiment, engine-run, and "
    "command-invocation lifecycles, queue-time immutability, revision "
    "compare-and-swap, the immutable six-gate retry decision with durable delay "
    "and successor creation, deterministic terminal aggregation, and "
    "application-owned repository and unit-of-work ports exercised through "
    "in-memory doubles are implemented. Stage 5 implementation completed at "
    f"`{STAGE5_IMPLEMENTATION_COMMIT}`; the seven Stage 5 schemas, the reviewed "
    "27-schema registry, the Stage 5 architecture and safety guards, the "
    "end-to-end in-memory flow, and this status were added by the separate "
    "Task 9 commit, which is not the implementation hash. Stage 6 has not "
    "started."
)
_VERIFICATION_STAGE5_STATUS = "\n".join(
    (
        "Project 1 Stage 5 is complete. Stage 5 implementation completed at",
        f"`{STAGE5_IMPLEMENTATION_COMMIT}`; the seven Stage 5 schemas, the",
        "closed 27-schema registry, the Stage 5 architecture and safety guards, the",
        "end-to-end in-memory flow, and this status were added by the separate Task 9",
        "commit, which is not the implementation hash. The closed 27-schema registry",
        "holds the seven new Stage 5 schemas together with the twenty Stage 3 and",
        "Stage 4 schemas, preserved byte-identical to `main`. Stage 6 is not started.",
    )
)
_STAGE5_ROADMAP_STATUS_LINE = (
    "**Status:** Approved planning decomposition; Stages 1 through 5 complete"
)
_STAGE5_ROADMAP_PLAN_SENTENCE = (
    "Stages 1 through 5 have approved detailed implementation plans."
)
#: Plan section 2.7: the implementation cell is the plan's, verbatim; the exit-gate
#: cell, which the plan elides, carries the Task 9 attribution.
_STAGE5_ROADMAP_ROW = (
    "| 5 — Experiment, Run, Invocation, Retry, and Aggregation Logic | Approved "
    "and executed | Implementation complete at "
    f"`{STAGE5_IMPLEMENTATION_COMMIT}` | Complete; strict lifecycle records and "
    "exhaustive transition tables for experiments, engine runs, and command "
    "invocations, queue-time immutability, revision compare-and-swap, the "
    "immutable six-gate retry decision with durable delay and successor "
    "creation, deterministic terminal aggregation, and application-owned "
    "repository and unit-of-work ports exercised through in-memory doubles; "
    "the closed 27-schema registry — 7 new Stage 5 schemas with the 20 Stage 3 "
    "and Stage 4 schemas preserved byte-identical — together with the Stage 5 "
    "architecture and safety guards, the end-to-end in-memory flow, and this "
    "status were added by the separate Task 9 commit, which is not the "
    "implementation hash; verified offline on the complete verifier, which "
    "passed on its first attempt; GitNexus remains `DISABLED_WITH_EVIDENCE` "
    "with the manual source, reference, and diff fallback recorded; Stage 6 "
    # Stage 6 plan section 2.6: the one clause of this row Task 9 changes.
    "complete |"
)
_STAGE5_DEFERRED_ROW = (
    "| 5 — Experiment, Run, Invocation, Retry, and Aggregation Logic | "
    "Intentionally deferred until Stages 3\u20134 completion | Not started | "
    "Not evaluated |"
)

# --- Stage 6 Task 9: the completion-status successors of plan section 2.6 ---------
#
# The Stage 6 implementation hash is the Task 8 commit, the last commit that adds
# Stage 6 behaviour. Plan section 2.6 requires Task 9 to introduce this constant in
# the same commit that changes the prose and section 14 makes Task 9 one commit, so
# the constant cannot name the Task 9 commit itself (a commit cannot contain its own
# hash; the Stage 4 and Stage 5 rules). Every surface that names the hash also says,
# in the same sentence, that the eight Stage 6 protocol schemas, the closed 35-schema
# registry, the Stage 6 boundary guard, the end-to-end protocol flow and the status
# itself were added by the separate Task 9 commit, which is not the implementation
# hash; that commit's hash is reported in the completion report and the merge
# evidence, never written into its own tree.
STAGE6_IMPLEMENTATION_COMMIT = "539e96bbba4cad0747dba5dc12ea3d74318d1c83"
STAGE6_PLAN = (
    "docs/superpowers/plans/2026-08-10-project-1-adapter-protocol-fake-adapter-"
    "contract-harness-implementation-plan.md"
)
_README_STAGE6_STATUS = (
    "Project 1 Stage 6 is complete. Explicit adapter catalog contracts, bootstrap "
    "descriptors and protocol negotiation, command-discriminated request envelopes, "
    "invocation-scoped stdout events with sequence, replay, and identity rules, "
    "validation results, untrusted adapter result manifests reconciled into "
    "core-sanitized manifests, stable exit mappings, raw-token redaction, and "
    "executable fake adapters covering the contract matrix are implemented. "
    "Stage 6 implementation completed at "
    f"`{STAGE6_IMPLEMENTATION_COMMIT}`; the eight Stage 6 protocol schemas, the "
    "closed 35-schema registry, the Stage 6 boundary guard, the end-to-end "
    "protocol flow, and this status were added by the separate Task 9 commit, "
    "which is not the implementation hash. The fake adapters run only through the "
    "test-resident harness, never through a production supervisor. Stage 7 has "
    "not started."
)
_VERIFICATION_STAGE6_STATUS = "\n".join(
    (
        "Project 1 Stage 6 is complete. Stage 6 implementation completed at",
        f"`{STAGE6_IMPLEMENTATION_COMMIT}`; the eight Stage 6 protocol",
        "schemas, the closed 35-schema registry, the Stage 6 boundary guard, the",
        "end-to-end protocol flow, and this status were added by the separate Task 9",
        "commit, which is not the implementation hash. The fake adapters run only",
        "through the test-resident harness, never through a production supervisor.",
        "The closed 35-schema registry holds the eight new Stage 6 schemas together",
        "with the twenty-seven Stage 3, 4 and 5 schemas, preserved byte-identical to",
        "`main`. Stage 7 is not started.",
    )
)
#: Stage 6 plan section 2.6: the one legitimate "Stage 7" sentence of the
#: verification guide while Stage 7 was not started; Stage 7 plan section 2.6 keeps
#: its positive pin and still subtracts it before the containment assertion.
_VERIFICATION_STAGE7_SENTENCE = (
    "Stage 7 retains physical ancestor reparse-point and volume containment."
)
_STAGE6_ROADMAP_STATUS_LINE = (
    "**Status:** Approved planning decomposition; Stages 1 through 6 complete"
)
_STAGE6_ROADMAP_PLAN_SENTENCE = (
    "Stages 1 through 6 have approved detailed implementation plans."
)

# --- Stage 7 Task 9: the completion-status successors of plan section 2.6 ---------
#
# The Stage 7 implementation hash is the Task 8 commit, the last commit that adds
# Stage 7 behaviour. Plan section 2.6 requires Task 9 to introduce this constant in
# the same commit that changes the prose and section 14 makes Task 9 one commit, so
# the constant cannot name the Task 9 commit itself (a commit cannot contain its own
# hash; the Stage 4, 5 and 6 rules). Every surface that names the hash also says, in
# the same sentence, that the Stage 7 boundary guard and the status itself were added
# by the separate Task 9 commit, which is not the implementation hash; Task 9 adds no
# schema and no flow test (plan section 9.6), so the sentence names neither. That
# commit's hash is reported in the completion report and the merge evidence, never
# written into its own tree.
STAGE7_IMPLEMENTATION_COMMIT = "c1b17e481e9e1c192d4cae0a70764bf4d643515a"
STAGE7_PLAN = (
    "docs/superpowers/plans/2026-08-10-project-1-windows-process-supervision-"
    "implementation-plan.md"
)
_README_STAGE7_STATUS = (
    "Project 1 Stage 7 is complete. Shell-free absolute argument-array launch with a "
    "fresh empty environment, bounded stdout and stderr readers, incremental protocol "
    "parsing, paired UTC and monotonic deadlines, heartbeat liveness, graceful and "
    "forced termination with Job Object process-tree cleanup, durable PID creation "
    "identity, path preflight, stale-invocation rejection, and restart reconciliation "
    "are implemented. Stage 7 implementation completed at "
    f"`{STAGE7_IMPLEMENTATION_COMMIT}`; the Stage 7 boundary guard and this status "
    "were added by the separate Task 9 commit, which is not the implementation hash. "
    "No schema was added: the closed 35-schema registry is preserved byte-identical. "
    "The fake adapters run through the production supervisor as well as the "
    "test-resident stand-in. Stage 8 has not started."
)
_VERIFICATION_STAGE7_STATUS = "\n".join(
    (
        "Project 1 Stage 7 is complete. Shell-free absolute argument-array launch with",
        "a fresh empty environment, bounded stdout and stderr readers, incremental",
        "protocol parsing, paired UTC and monotonic deadlines, heartbeat liveness,",
        "graceful and forced termination with Job Object process-tree cleanup, durable",
        "PID creation identity, path preflight, stale-invocation rejection, and",
        "restart reconciliation are implemented. Stage 7 implementation completed at",
        f"`{STAGE7_IMPLEMENTATION_COMMIT}`; the Stage 7 boundary guard and",
        "this status were added by the separate Task 9 commit, which is not the",
        "implementation hash. No schema was added: the closed 35-schema registry is",
        "preserved byte-identical. The fake adapters run through the production",
        "supervisor as well as the test-resident stand-in. Stage 8 is not started.",
    )
)
_STAGE7_ROADMAP_STATUS_LINE = (
    "**Status:** Approved planning decomposition; Stages 1 through 7 complete"
)
_STAGE7_ROADMAP_PLAN_SENTENCE = (
    "Stages 1 through 7 have approved detailed implementation plans."
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
    # Stage 5 plan section 2.7 advanced these two pins to their Stage 5 successors;
    # Stage 6 plan section 2.6 advanced them again in Task 9, here and in every
    # other occurrence; Stage 7 plan section 2.6 advanced them once more in its
    # Task 9. Pairs, not swaps: the retired forms are denied.
    assert _STAGE7_ROADMAP_STATUS_LINE in roadmap
    assert _STAGE7_ROADMAP_PLAN_SENTENCE in roadmap
    assert _STAGE6_ROADMAP_STATUS_LINE not in roadmap
    assert _STAGE6_ROADMAP_PLAN_SENTENCE not in roadmap
    assert _STAGE5_ROADMAP_STATUS_LINE not in roadmap
    assert _STAGE5_ROADMAP_PLAN_SENTENCE not in roadmap
    assert _STAGE4_ROADMAP_STATUS_LINE not in roadmap
    assert _STAGE4_ROADMAP_PLAN_SENTENCE not in roadmap
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
    # The Stage 4 transition, per the plan section 3.9 status-authority rule.
    # A pair, not a swap: the positive pin alone would pass on a roadmap that
    # carried both the new row and a stale leftover copy of the retired phrase.
    assert _STAGE4_ROADMAP_ROW in roadmap
    assert "Eligible for just-in-time planning after Stage 3 completion" not in roadmap
    assert "`DISABLED_WITH_EVIDENCE`" in roadmap
    # The one assertion Task 8 is authorized to update, per the plan section 3.9
    # status-authority rule, and only in the same commit that updates README.md.
    # It becomes that string verbatim -- no additional assertion is added here,
    # because plan step 6 enumerates exactly two Task 8 edits to this module.
    # Every Stage 3 assertion above it stays verbatim. Stage 5 plan section 2.7
    # advanced the string to its Stage 5 successor in Task 9; Stage 6 plan section
    # 2.6 advanced it to the Stage 6 successor in Task 9; Stage 7 plan section 2.6
    # advanced it to the Stage 7 successor in Task 9.
    assert "**Status:** Project 1 Stages 1-7 complete" in readme
    assert "**Status:** Project 1 Stages 1-6 complete" not in readme
    assert "**Status:** Project 1 Stages 1-5 complete" not in readme
    assert "**Status:** Project 1 Stages 1-4 complete" not in readme


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
    assert _STAGE4_ROADMAP_ROW in roadmap

    # Section 11 item 3 must stay directional. Reverting it to the symmetric
    # "within one point" band removes this sentence and fails here.
    assert _STAGE4_COVERAGE_SENTENCE in plan

    # Stage 4 implementation is complete; Stages 5, 6 and 7 are complete too (each
    # stage's Task 9), so the Stage 5 row is its completion row with the Stage 6
    # clause and the deferred row is gone. A pair, not a swap, for the same reason
    # as the Stage 4 transition above.
    assert _STAGE7_ROADMAP_STATUS_LINE in roadmap
    assert _STAGE5_ROADMAP_ROW in roadmap
    assert _STAGE5_DEFERRED_ROW not in roadmap


def test_stage7_completion_status_is_exact(repository_root: Path) -> None:
    """One test, three surfaces, so no surface can drift alone (Stage 7 plan 2.6).

    The Stage 6 test of the same shape became this one in Task 9, with exactly the
    successors plan section 2.6 tabulates: positive pins are byte-exact, following
    the hard-wrapped comparison in
    ``test_readme_uses_only_closed_stage3_launcher_setup``; the Stage 4, Stage 5
    and Stage 6 hashes stay pinned in the roadmap's history rows only and keep their
    own distinctness assertions; the two containment assertions now forbid any
    "Stage 8" claim outside the pinned blocks, which is the exact contract that
    "Stage 8 not started" appears only where it is pinned and no other Stage 8
    claim exists -- the guide's Stage 7 containment sentence keeps its positive
    pin and is subtracted with the blocks. The subtracted blocks are the only place
    permitted to say "exhaustive". The Stage 7 completion row, the Stage 8 deferred
    row and the Stage 7 plan-approval line are pinned by the Task 9-owned
    ``tests/safety/test_stage7_boundaries.py``; the Stage 6 completion row's
    "Stage 7 complete" clause by ``tests/safety/test_stage6_boundaries.py``.
    """
    earlier = {
        STAGE3_TASK8_COMMIT,
        STAGE3_IMPLEMENTATION_COMMIT,
        STAGE3_STABILITY_CORRECTION_COMMIT,
        STAGE4_LAUNCHER_BOOTSTRAP_COMMIT,
        STAGE4_PLAN_APPROVAL_COMMIT,
        STAGE4_EVALUATOR_CORRECTION_COMMIT,
        *STAGE4_PLAN_CORRECTION_COMMITS,
        *STAGE4_REVIEW_FOLLOWUP_COMMITS,
    }
    assert re.fullmatch(r"[0-9a-f]{40}", STAGE7_IMPLEMENTATION_COMMIT) is not None
    assert STAGE7_IMPLEMENTATION_COMMIT not in earlier | {
        STAGE4_IMPLEMENTATION_COMMIT,
        STAGE5_IMPLEMENTATION_COMMIT,
        STAGE6_IMPLEMENTATION_COMMIT,
    }
    assert re.fullmatch(r"[0-9a-f]{40}", STAGE6_IMPLEMENTATION_COMMIT) is not None
    assert STAGE6_IMPLEMENTATION_COMMIT not in earlier | {
        STAGE4_IMPLEMENTATION_COMMIT,
        STAGE5_IMPLEMENTATION_COMMIT,
    }
    assert re.fullmatch(r"[0-9a-f]{40}", STAGE5_IMPLEMENTATION_COMMIT) is not None
    assert STAGE5_IMPLEMENTATION_COMMIT not in earlier | {STAGE4_IMPLEMENTATION_COMMIT}
    assert re.fullmatch(r"[0-9a-f]{40}", STAGE4_IMPLEMENTATION_COMMIT) is not None
    assert STAGE4_IMPLEMENTATION_COMMIT not in earlier

    roadmap = (repository_root / STAGE4_ROADMAP).read_text(encoding="utf-8")
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    guide = (repository_root / STAGE4_VERIFICATION_GUIDE).read_text(encoding="utf-8")

    assert _STAGE7_ROADMAP_STATUS_LINE in roadmap
    assert _STAGE7_ROADMAP_PLAN_SENTENCE in roadmap
    assert _STAGE6_ROADMAP_STATUS_LINE not in roadmap
    assert _STAGE6_ROADMAP_PLAN_SENTENCE not in roadmap
    assert _STAGE5_ROADMAP_STATUS_LINE not in roadmap
    assert _STAGE5_ROADMAP_PLAN_SENTENCE not in roadmap
    assert _STAGE4_ROADMAP_ROW in roadmap
    assert _STAGE5_ROADMAP_ROW in roadmap
    assert f"**Approved detailed implementation plan:** `{STAGE7_PLAN}`." in roadmap
    assert f"**Planned detailed implementation plan:** `{STAGE7_PLAN}`." not in roadmap

    assert _README_STAGE7_STATUS in readme
    assert _VERIFICATION_STAGE7_STATUS in guide
    assert _VERIFICATION_CORPUS_QUALIFICATION in guide
    assert _VERIFICATION_NON_GOALS in guide
    assert _VERIFICATION_STAGE7_SENTENCE in guide
    assert _README_STAGE4_STATUS not in readme
    assert _README_STAGE5_STATUS not in readme
    assert _README_STAGE6_STATUS not in readme
    assert _VERIFICATION_STAGE4_STATUS not in guide
    assert _VERIFICATION_STAGE5_STATUS not in guide
    assert _VERIFICATION_STAGE6_STATUS not in guide

    for phrase in _RETIRED_STATUS_PHRASES:
        assert phrase not in readme
        assert phrase not in guide

    # The same implementation hash on every surface, asserted separately so
    # changing it in exactly one file fails here and names that file. The roadmap
    # keeps the Stage 4, Stage 5 and Stage 6 hashes in its history rows; README and
    # the guide carry the Stage 7 hash alone.
    assert STAGE7_IMPLEMENTATION_COMMIT in roadmap
    assert STAGE7_IMPLEMENTATION_COMMIT in readme
    assert STAGE7_IMPLEMENTATION_COMMIT in guide
    assert STAGE6_IMPLEMENTATION_COMMIT in roadmap
    assert STAGE6_IMPLEMENTATION_COMMIT not in readme
    assert STAGE6_IMPLEMENTATION_COMMIT not in guide
    assert STAGE5_IMPLEMENTATION_COMMIT in roadmap
    assert STAGE5_IMPLEMENTATION_COMMIT not in readme
    assert STAGE5_IMPLEMENTATION_COMMIT not in guide
    assert STAGE4_IMPLEMENTATION_COMMIT in roadmap
    assert STAGE4_IMPLEMENTATION_COMMIT not in readme
    assert STAGE4_IMPLEMENTATION_COMMIT not in guide

    # Containment. Remove the pinned blocks, then scan what is left. Scoped to
    # the two documentation files, never the roadmap: the roadmap carries its
    # own Stage 8 rows, and "exhaustive" occurs there legitimately.
    readme_rest = readme.replace(_README_STAGE7_STATUS, "")
    guide_rest = (
        guide.replace(_VERIFICATION_STAGE7_STATUS, "")
        .replace(_VERIFICATION_CORPUS_QUALIFICATION, "")
        .replace(_VERIFICATION_STAGE7_SENTENCE, "")
    )
    assert "Stage 8" not in readme_rest
    assert "Stage 8" not in guide_rest
    assert "exhaustiv" not in readme_rest.lower()
    assert "exhaustiv" not in guide_rest.lower()
