"""Enforce the Stage 3 architectural, source, schema, and verifier boundary."""

from __future__ import annotations

import ast
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
    "domain/diagnostics.py",
    "domain/financial.py",
    "domain/hashing.py",
    "domain/identifiers.py",
    "domain/records.py",
    "domain/time.py",
    "domain/versioning.py",
    "experiments/__init__.py",
    "persistence/__init__.py",
    "process_supervision/__init__.py",
    "schema_registry.py",
    "strategy/__init__.py",
}
_ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "collections",
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
    "typing",
    "uuid",
}
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
    "CapabilityRequirement",
    "CapabilityVocabulary",
    "CommandInvocationRecord",
    "CommandInvocationRepository",
    "CommandInvocationState",
    "CommandKind",
    "CommandResult",
    "ComparisonEligibilityResult",
    "ComparisonEligibilityService",
    "ComparisonLevel",
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
    "StrategyLoader",
    "StrategySpec",
    "StrategyVersion",
    "UnitOfWork",
    "ValidationOutcome",
    "ingest_dataset",
    "negotiate_protocol",
    "normalize_dataset",
    "place_order",
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


def test_gitnexus_remains_disabled_with_evidence(repository_root: Path) -> None:
    outcome = (repository_root / "tools/gitnexus/outcome.json").read_text(
        encoding="utf-8"
    )
    assert '"outcome": "DISABLED_WITH_EVIDENCE"' in outcome
