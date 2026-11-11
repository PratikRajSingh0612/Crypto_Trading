"""Enforce the Stage 9 artifact, audit and finalization boundary and record Stage 9
completion.

Stage 9 plan section 2.6 and Task 9. The guard pins the twenty-five Stage 9 source
modules (the Task-3-excluded branch of the plan's branch table; disjoint from the
Stage 5, 6, 7 and 8 sets), proves ``artifacts`` and ``audit`` import ``domain`` and
themselves alone, pins the exact ``experiments`` modules that reach the two new
packages and that ``retry.py`` reaches neither, keeps every package the plan names
away from them, confines ``os`` to ``artifacts/store.py`` and to the two attributes
``fstat`` and ``fsync``, denies the fifteen roots no new module may import, the
raw-token annotation, the four bare identifiers and the dynamic-code surface, proves
each of the twenty released names is defined exactly once in its section 2.6 module
and that the thirteen still-deferred names are defined nowhere, pins the
``HashingProfile`` tail, the thirteen Stage 9 schema entries at positions 35-47 with
their digests, the one Alembic head and the closed ``AuditAction`` vocabulary, and
records the roadmap, README and guide status of a complete Stage 9 with Stage 10 not
started.

Declared readings, so nothing is inferred silently:

- The recorded Task 3 disposition is the plan's default (section 1.6 item 1:
  exclude). No human confirmation exists in the tree, ``domain/normalized.py`` does
  not exist and every guard already pins the excluded column of the section 2.6
  branch table, so this guard pins that column: 25 Stage 9 source files, 135
  allowed source files, 48 schemas, 13 new schemas, 20 released names and 13
  deferred names.
- "``experiments`` imports ``artifacts``/``audit`` only from the three new
  modules" is an upper bound; the committed tree reaches them from exactly two,
  ``experiments/finalization.py`` (both) and ``experiments/run_manifest.py``
  (``artifacts``), while ``experiments/comparison.py`` consumes ``RunManifest``
  through ``experiments/run_manifest.py`` and imports neither package directly.
  The exact two-module set is pinned, which satisfies the bound and refuses a
  third importer.
- The thirteen digests live in ``tests/unit/test_schema_registry.py``
  (``_STAGE9_SHA256``, plan section 2.6 "Schema registry"). That module is not
  importable from the safety tree, so the literal is read by AST
  (``ast.literal_eval`` of the one annotated assignment, the way the Stage 8 unit
  consumers read the Stage 3 guard) and every committed file is hashed against it
  here, so the digest block and the registry positions are cross-pinned without a
  second copy of the digests.
- The implementation hash lives in test constants and once in the roadmap; README
  and the guide refer readers to the roadmap's checkpoint and carry no Stage 9 hash
  (plan section 2.6 and Task 9 step 3). "Stage 10" may appear in README
  only inside the pinned status block and in the guide only inside the pinned
  status and obligations blocks (the Stage 3 guard owns that containment); the
  roadmap carries its own Stage 10 rows, so it is scanned only for the five
  later-stage claims and never for "exhaustiv".
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Final

import pytest
from test_stage3_boundaries import (
    _ALLOWED_IMPORT_ROOTS,
    _ALLOWED_SOURCE_FILES,
    _DEFERRED_DEFINITIONS,
    _README_STAGE8_STATUS,
    _README_STAGE9_STATUS,
    _STAGE9_ROADMAP_PLAN_SENTENCE,
    _STAGE9_ROADMAP_STATUS_LINE,
    _STAGE9_TASK1_RELEASED_DEFINITIONS,
    _STAGE9_TASK2_RELEASED_DEFINITIONS,
    _STAGE9_TASK4_RELEASED_DEFINITIONS,
    _STAGE9_TASK6_RELEASED_DEFINITIONS,
    _STAGE9_TASK7_RELEASED_DEFINITIONS,
    _VERIFICATION_CORPUS_QUALIFICATION,
    _VERIFICATION_STAGE8_STATUS,
    _VERIFICATION_STAGE9_OBLIGATIONS,
    _VERIFICATION_STAGE9_STATUS,
    STAGE4_IMPLEMENTATION_COMMIT,
    STAGE5_IMPLEMENTATION_COMMIT,
    STAGE6_IMPLEMENTATION_COMMIT,
    STAGE7_IMPLEMENTATION_COMMIT,
    STAGE8_IMPLEMENTATION_COMMIT,
    STAGE9_IMPLEMENTATION_COMMIT,
    STAGE9_PLAN,
    _imported_roots,
    _source_files,
)
from test_stage5_boundaries import STAGE5_SOURCE_FILES, _parse
from test_stage6_boundaries import (
    _SUBPROCESS_IMPORTERS,
    STAGE6_SOURCE_FILES,
    _attempt_token_fields,
)
from test_stage7_boundaries import STAGE7_SOURCE_FILES, _defined_names
from test_stage8_boundaries import (
    _BASELINE_REVISION,
    _STAGE8_COMPLETION_ROW,
    _STAGE9_DEFERRED_ROW,
    _STAGE9_PERSISTENCE_FILES,
    _STAGE9_REVISION,
    _VERSIONS_DIRECTORY,
    STAGE8_SOURCE_FILES,
    _bare_identifier_violations,
    _crypto_lab_imports,
    _focused_command,
    _label,
    _read,
    _revision_bindings,
    _source_path,
)

from crypto_lab.audit.models import AuditAction
from crypto_lab.domain.hashing import HashingProfile
from crypto_lab.persistence.migration_runner import expected_head
from crypto_lab.schema_registry import SCHEMA_DEFINITIONS

#: Plan section 2.6 (source-file allowlist): the twenty-five paths Stage 9 added on
#: the Task-3-excluded branch, in the order of the table (Tasks 1, 2, 4, 5, 6, 7).
STAGE9_SOURCE_FILES: Final[tuple[str, ...]] = (
    "artifacts/models.py",
    "artifacts/requests.py",
    "artifacts/journal.py",
    "artifacts/manifest.py",
    "artifacts/diagnostics.py",
    "audit/models.py",
    "audit/redaction.py",
    "audit/correlation.py",
    "audit/jsonl.py",
    "audit/sink.py",
    "domain/metrics.py",
    "artifacts/paths.py",
    "artifacts/hashing.py",
    "artifacts/validation.py",
    "artifacts/store.py",
    "persistence/artifact_codecs.py",
    "persistence/artifact_repositories.py",
    "persistence/audit_sink.py",
    "persistence/migrations/versions/r0002_stage9_artifacts.py",
    "artifacts/ports.py",
    "artifacts/finalizer.py",
    "artifacts/recovery.py",
    "experiments/run_manifest.py",
    "experiments/finalization.py",
    "experiments/comparison.py",
)
#: The conditional Task 3 module, absent on the recorded branch.
_TASK3_MODULE: Final = "domain/normalized.py"
#: The merged artifact modules that predate Stage 9 and share the package closure.
_ARTIFACTS_PACKAGE_MODULES: Final[frozenset[str]] = frozenset(
    {"artifacts/__init__.py", "artifacts/ownership.py"}
)
_AUDIT_PACKAGE_INIT: Final = "audit/__init__.py"
#: Plan 9.3 item 14: the ``experiments`` modules that may reach the two new packages
#: (the three Task 7 modules) and the two that do (declared reading 2).
_EXPERIMENTS_PERMITTED_IMPORTERS: Final[frozenset[str]] = frozenset(
    {
        "experiments/run_manifest.py",
        "experiments/finalization.py",
        "experiments/comparison.py",
    }
)
_EXPERIMENTS_ACTUAL_IMPORTERS: Final[frozenset[str]] = frozenset(
    {"experiments/run_manifest.py", "experiments/finalization.py"}
)
_RETRY_MODULE: Final = "experiments/retry.py"
#: Plan 9.3 item 14: the packages that import neither new package.
_PACKAGES_DENIED_THE_NEW_PACKAGES: Final[tuple[str, ...]] = (
    "process_supervision",
    "adapters",
    "domain",
    "strategy",
    "capabilities",
    "configuration",
    "datasets",
)
_NEW_PACKAGES: Final[frozenset[str]] = frozenset({"artifacts", "audit"})
#: Plan section 2.6 (import-root table): the one importer of ``os`` and its reads.
_OS_IMPORTER: Final = "artifacts/store.py"
_OS_ATTRIBUTES: Final[frozenset[str]] = frozenset({"fstat", "fsync"})
#: Plan section 2.6 (import-root allowlist): the roots no new module imports.
_DENIED_ROOTS: Final[frozenset[str]] = frozenset(
    {
        "stat",
        "shutil",
        "tempfile",
        "io",
        "errno",
        "logging",
        "time",
        "secrets",
        "random",
        "threading",
        "asyncio",
        "ctypes",
        "queue",
        "subprocess",
        "types",
    }
)
#: Plan Task 9 step 1: no serialization-by-code and no dynamic evaluation.
_DYNAMIC_CODE_ROOTS: Final[frozenset[str]] = frozenset(
    {"pickle", "marshal", "shelve", "dill"}
)
_DYNAMIC_CODE_CALLS: Final[frozenset[str]] = frozenset(
    {"eval", "exec", "compile", "__import__"}
)
#: Plan section 2.6 (released-names table), the excluded branch: the union of the
#: five per-task positives of the Stage 3 guard, twenty names.
_RELEASED_DEFINITIONS: Final[dict[str, str]] = {
    **_STAGE9_TASK1_RELEASED_DEFINITIONS,
    **_STAGE9_TASK2_RELEASED_DEFINITIONS,
    **_STAGE9_TASK4_RELEASED_DEFINITIONS,
    **_STAGE9_TASK6_RELEASED_DEFINITIONS,
    **_STAGE9_TASK7_RELEASED_DEFINITIONS,
}
#: Plan section 3.2: the eight profiles Stage 9 appended, in order.
_STAGE9_HASHING_PROFILES: Final[tuple[str, ...]] = (
    "ARTIFACT_IDENTITY_V1",
    "ARTIFACT_MANIFEST_V1",
    "CANDIDATE_SET_V1",
    "FINALIZATION_IDENTITY_V1",
    "CORE_CANDIDATE_IDENTITY_V1",
    "AUDIT_EVENT_DETAILS_V1",
    "RUN_MANIFEST_V1",
    "RUN_MANIFEST_IDENTITY_V1",
)
#: Plan section 3.2: the thirteen schema entries of the excluded branch at positions
#: 35-47 (Task 1 eight, Task 2 three, Task 7 two), in registry order.
_STAGE9_SCHEMA_PATHS: Final[tuple[str, ...]] = (
    "artifacts/candidate-artifact-v1.schema.json",
    "artifacts/artifact-ref-v1.schema.json",
    "artifacts/artifact-finalization-purpose-v1.schema.json",
    "artifacts/artifact-manifest-v1.schema.json",
    "artifacts/result-finalization-request-v1.schema.json",
    "artifacts/evidence-finalization-request-v1.schema.json",
    "artifacts/finalization-result-v1.schema.json",
    "artifacts/finalization-journal-entry-v1.schema.json",
    "audit/audit-event-v1.schema.json",
    "audit/log-record-v1.schema.json",
    "domain/metric-value-v1.schema.json",
    "experiments/run-manifest-v1.schema.json",
    "experiments/normalized-result-provenance-v1.schema.json",
)
_SCHEMA_REGISTRY_TEST: Final = "tests/unit/test_schema_registry.py"
_DIGEST_LITERAL: Final = "_STAGE9_SHA256"
#: Plan section 3.2: the closed set of 25 audit actions, in declaration order.
_AUDIT_ACTIONS: Final[tuple[str, ...]] = (
    "ARTIFACT_CANDIDATE_REGISTERED",
    "ARTIFACT_VALIDATED",
    "ARTIFACT_VALIDATION_FAILED",
    "ARTIFACT_OWNER_PURPOSE_SELECTED",
    "FINALIZATION_LEASE_ACQUIRED",
    "FINALIZATION_LEASE_REFUSED",
    "FINALIZATION_PREPARED",
    "FINALIZATION_MOVED",
    "FINALIZATION_REGISTERED",
    "FINALIZATION_REPLAYED",
    "FINALIZATION_ABANDONED",
    "FINALIZATION_TIMED_OUT",
    "ARTIFACT_QUARANTINED",
    "ARTIFACT_CORRUPT",
    "ARTIFACT_LEAKAGE_DETECTED",
    "RUN_SUCCEEDED",
    "RUN_FAILED",
    "RUN_MANIFEST_REGISTERED",
    "STDERR_TRUNCATED",
    "STDERR_EVIDENCE_LINKED",
    "RECONCILIATION_FINALIZATION_RESUMED",
    "RECONCILIATION_CANDIDATE_QUARANTINED",
    "RECONCILIATION_ORPHAN_QUARANTINED",
    "RETENTION_DELETED",
    "QUARANTINE_OVERDUE",
)
_ROADMAP: Final = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
_VERIFICATION_GUIDE: Final = "docs/development/verification.md"
_README: Final = "README.md"
#: Plan section 2.6 (status pins): the Stage 9 completion row; the implementation
#: hash is the Task 8 commit, written once in the roadmap and nowhere else.
_STAGE9_COMPLETION_ROW: Final = (
    "| 9 — Artifact Finalization, Recovery, Provenance, and Audit | Approved and "
    f"executed | Implementation complete at `{STAGE9_IMPLEMENTATION_COMMIT}` | "
    "Complete; candidate and finalized artifact records with disjoint `RESULT` and "
    "`EVIDENCE` identities, owner, purpose and role validation over the seven-row "
    "table, lexical and physical path confinement with reparse-point, link and "
    "alternate-data-stream defenses, streaming hashing with the exact-byte token "
    "scan, the content-addressed store with same-volume atomic moves, the "
    "purpose-tagged finalization journal with its four-transaction protocol, crash "
    "recovery over every crash point and quarantine, the core `RunManifest` created "
    "only for a successful run, normalized result provenance, diagnostic causal "
    "chains, the bounded rotated JSON Lines log, append-only audit events and the "
    "post-run raw-token scans, with the success, warning, failure, cancellation, "
    "finalization-timeout, crash-point and recovery rows driven through the "
    "production supervisor over the SQLite database and all six owner variants "
    "exercised through the production finalization path, the four beyond `RUN` and "
    "`ADAPTER` with test-supplied bytes; the closed "
    "48-schema registry — 13 new Stage 9 schemas with the 35 Stage 3, 4, 5 and 6 "
    "schemas preserved byte-identical — and the relational head "
    "`r0002_stage9_artifacts` over the unchanged Stage 8 baseline; the Stage 9 "
    "boundary guard, the Stage 9 focused checks and status pins and this status "
    "were added by the separate Task 9 commit, which is not the implementation "
    "hash; verified offline on the complete verifier; GitNexus remains "
    "`DISABLED_WITH_EVIDENCE` with the manual source, reference, and diff fallback "
    "recorded; Stage 10 not started |"
)
_STAGE10_DEFERRED_ROW: Final = (
    "| 10 — CLI Composition and End-to-End Acceptance | Intentionally deferred "
    f"until Stages 4{chr(0x2013)}9 completion | Not started | Not evaluated |"
)
_LATER_STAGE_CLAIMS: Final[tuple[str, ...]] = (
    "Stage 10 has started",
    "Stage 10 is complete",
    "Stage 10 complete",
    "Stages 1-10",
    "Stages 1 through 10",
)
#: The guide's Stage 9 focused-check paragraph and the six plan 9.1 targets the
#: command lines are generated from.
_VERIFICATION_STAGE9_FOCUSED_PROSE: Final = "\n".join(
    (
        "Stage 9's focused targets are the following. `tests\\unit\\artifacts`,",
        "`tests\\unit\\audit`, `tests\\integration\\artifacts`, the Stage 9 modules "
        "under",
        "`tests\\unit\\persistence`, `tests\\unit\\experiments`,",
        "`tests\\integration\\persistence` and `tests\\property`,",
        "`tests\\doubles\\artifacts.py`, `tests\\persistence_support\\artifacts.py` "
        "and",
        "`tests\\safety\\test_stage9_boundaries.py` are new in Stage 9; "
        "`tests\\unit\\domain`,",
        "`tests\\unit\\persistence`, `tests\\unit\\experiments`,",
        "`tests\\integration\\persistence`, `tests\\property`, `tests\\safety`,",
        "`tests\\architecture` and `tests\\unit\\test_schema_registry.py` are older "
        "modules",
        "whose contract Stage 9 widened from 35 schemas to 48 and extended with the",
        "artifact, audit and metric contracts, the Stage 9 persistence increments, the",
        "result registrar and the evidence producers, the finalizing supervised flow "
        "and",
        "the Stage 9 boundary guard; the relational schema has one Alembic head,",
        "`r0002_stage9_artifacts`, the single successor of the Stage 8 baseline.",
    )
)
_STAGE9_FOCUSED_TARGETS: Final[tuple[tuple[str, ...], ...]] = (
    ("tests\\unit\\artifacts", "tests\\unit\\audit"),
    ("tests\\unit\\persistence", "tests\\unit\\domain"),
    ("tests\\integration\\artifacts",),
    ("tests\\unit\\experiments", "tests\\property"),
    ("tests\\integration\\persistence",),
    ("tests\\safety", "tests\\architecture", "tests\\unit\\test_schema_registry.py"),
)
_REGISTER_HEADING: Final = "### Runtime rules the Stage 9 schemas cannot express"
_CLOSED_REGISTRY_SENTENCE: Final = "closed 48-file registry"
_README_REGISTRY_SENTENCE: Final = "The registry is closed at **48** schemas"


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def _own_package(label: str) -> str:
    return label.split("/")[0]


def _package_closure_violations(
    tree: ast.AST, label: str, allowed_roots: Iterable[str]
) -> list[str]:
    """Every ``crypto_lab`` import whose first component is outside the allowed
    roots (``domain`` and the module's own package for the two new packages)."""
    allowed = frozenset(allowed_roots)
    return [
        f"{label}: import crypto_lab.{name} outside {sorted(allowed)}"
        for name in sorted(_crypto_lab_imports(tree, label))
        if name.partition(".")[0] not in allowed
    ]


def _new_package_imports(tree: ast.AST, label: str) -> frozenset[str]:
    """Which of the two new packages the module imports."""
    return frozenset(
        name.partition(".")[0]
        for name in _crypto_lab_imports(tree, label)
        if name.partition(".")[0] in _NEW_PACKAGES
    )


def _os_import_violations(tree: ast.AST, label: str) -> list[str]:
    """One plain ``import os``, never aliased, never ``from os import``."""
    violations: list[str] = []
    plain_imports = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.partition(".")[0] != "os":
                    continue
                if alias.name != "os" or alias.asname is not None:
                    violations.append(f"{label}:{node.lineno}: os imported as {alias}")
                else:
                    plain_imports += 1
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.partition(".")[0] == "os"
        ):
            violations.append(f"{label}:{node.lineno}: from-import of os")
    if plain_imports != 1:
        violations.append(f"{label}: {plain_imports} plain os imports")
    return violations


def _os_attribute_reads(tree: ast.AST) -> frozenset[str]:
    return frozenset(
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    )


def _denied_root_violations(tree: ast.AST, label: str) -> list[str]:
    return [
        f"{label}: denied root {root}"
        for root in sorted(set(_imported_roots(tree)) & _DENIED_ROOTS)
    ]


def _dynamic_code_violations(tree: ast.AST, label: str) -> list[str]:
    violations = [
        f"{label}: dynamic-code root {root}"
        for root in sorted(set(_imported_roots(tree)) & _DYNAMIC_CODE_ROOTS)
    ]
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _DYNAMIC_CODE_CALLS
        ):
            violations.append(f"{label}:{node.lineno}: dynamic call {node.func.id}()")
    return violations


def _literal_assignment(source: str, name: str) -> object:
    """The literal value of the one module-level assignment to ``name``."""
    for node in ast.parse(source).body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None:
            continue
        named = any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        )
        if named:
            return ast.literal_eval(value)
    raise AssertionError(f"no literal assignment to {name}")


def _digest_literal(repository_root: Path) -> dict[str, str]:
    source = _read(repository_root, _SCHEMA_REGISTRY_TEST)
    value = _literal_assignment(source, _DIGEST_LITERAL)
    assert isinstance(value, dict)
    digests: dict[str, str] = {}
    for key, digest in value.items():
        assert isinstance(key, str)
        assert isinstance(digest, str)
        digests[key] = digest
    return digests


def _definers(repository_root: Path, names: Iterable[str]) -> dict[str, list[str]]:
    wanted = frozenset(names)
    found: dict[str, list[str]] = {name: [] for name in sorted(wanted)}
    for path in _source_files(repository_root):
        label = _label(repository_root, path)
        for name in sorted(_defined_names(_parse(path)) & wanted):
            found[name].append(label)
    return found


def _stage9_trees(repository_root: Path) -> dict[str, ast.Module]:
    return {
        label: _parse(_source_path(repository_root, label))
        for label in STAGE9_SOURCE_FILES
    }


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# Source-tree facts
# --------------------------------------------------------------------------


def test_stage_nine_modules_are_exactly_the_plan_paths(repository_root: Path) -> None:
    assert len(STAGE9_SOURCE_FILES) == 25
    assert len(set(STAGE9_SOURCE_FILES)) == 25
    assert set(STAGE9_SOURCE_FILES) <= _ALLOWED_SOURCE_FILES
    for earlier in (
        STAGE5_SOURCE_FILES,
        STAGE6_SOURCE_FILES,
        STAGE7_SOURCE_FILES,
        STAGE8_SOURCE_FILES,
    ):
        assert set(STAGE9_SOURCE_FILES).isdisjoint(earlier)
    for relative_path in STAGE9_SOURCE_FILES:
        assert _source_path(repository_root, relative_path).is_file(), relative_path
    assert set(_STAGE9_PERSISTENCE_FILES) <= set(STAGE9_SOURCE_FILES)
    # The excluded branch: no Task 3 module, 135 files, and the planning base of
    # 110 minus the Stage 5-8 sets leaves the 51 pre-Stage-5 modules.
    assert _TASK3_MODULE not in _ALLOWED_SOURCE_FILES
    assert not _source_path(repository_root, _TASK3_MODULE).exists()
    assert len(_ALLOWED_SOURCE_FILES) == 135
    assert len(_source_files(repository_root)) == 135
    staged = set(STAGE9_SOURCE_FILES)
    for earlier in (
        STAGE5_SOURCE_FILES,
        STAGE6_SOURCE_FILES,
        STAGE7_SOURCE_FILES,
        STAGE8_SOURCE_FILES,
    ):
        staged |= set(earlier)
    assert len(_ALLOWED_SOURCE_FILES - staged) == 51
    assert _ARTIFACTS_PACKAGE_MODULES | {_AUDIT_PACKAGE_INIT} <= _ALLOWED_SOURCE_FILES


def test_artifacts_and_audit_import_domain_only(repository_root: Path) -> None:
    """Plan 9.3 item 14 and section 2.6 (architecture closure): every module of the
    two new packages, the merged ``ownership.py`` and both package markers
    included, imports ``domain`` and its own package alone."""
    violations: list[str] = []
    scanned = 0
    for path in _source_files(repository_root):
        label = _label(repository_root, path)
        package = _own_package(label)
        if package not in _NEW_PACKAGES:
            continue
        violations.extend(
            _package_closure_violations(_parse(path), label, ("domain", package))
        )
        scanned += 1
    assert violations == []
    # Fourteen artifact modules (twelve of Stage 9, the marker and `ownership.py`)
    # and six audit modules (five of Stage 9 and the marker).
    assert scanned == 14 + 6


def test_experiments_reach_the_new_packages_only_from_the_task_seven_modules(
    repository_root: Path,
) -> None:
    importers: dict[str, frozenset[str]] = {}
    experiments = repository_root / "src/crypto_lab/experiments"
    for path in sorted(experiments.rglob("*.py")):
        label = _label(repository_root, path)
        tree = _parse(path)
        reached = _new_package_imports(tree, label)
        if reached:
            importers[label] = reached
        roots = {name.partition(".")[0] for name in _crypto_lab_imports(tree, label)}
        assert "persistence" not in roots, label
    assert frozenset(importers) <= _EXPERIMENTS_PERMITTED_IMPORTERS
    assert frozenset(importers) == _EXPERIMENTS_ACTUAL_IMPORTERS
    assert importers["experiments/finalization.py"] == _NEW_PACKAGES
    assert importers["experiments/run_manifest.py"] == {"artifacts"}
    assert _RETRY_MODULE not in importers
    assert _RETRY_MODULE in _ALLOWED_SOURCE_FILES


def test_no_other_package_imports_the_new_packages(repository_root: Path) -> None:
    violations: list[str] = []
    for path in _source_files(repository_root):
        label = _label(repository_root, path)
        if _own_package(label) not in _PACKAGES_DENIED_THE_NEW_PACKAGES:
            continue
        for package in sorted(_new_package_imports(_parse(path), label)):
            violations.append(f"{label}: imports crypto_lab.{package}")
    assert violations == []


def test_os_is_confined_to_the_store_and_to_fstat_and_fsync(
    repository_root: Path,
) -> None:
    """Plan section 2.6 (import-root table), re-pinned here: the tree-wide
    importer set is exactly the store and its reads are exactly the two."""
    assert "os" in _ALLOWED_IMPORT_ROOTS
    assert len(_ALLOWED_IMPORT_ROOTS) == 30
    importers = [
        _label(repository_root, path)
        for path in _source_files(repository_root)
        if "os" in _imported_roots(_parse(path))
    ]
    assert importers == [_OS_IMPORTER]
    store = _parse(_source_path(repository_root, _OS_IMPORTER))
    assert _os_import_violations(store, _OS_IMPORTER) == []
    assert _os_attribute_reads(store) == _OS_ATTRIBUTES


def test_no_new_module_imports_a_denied_root(repository_root: Path) -> None:
    violations: list[str] = []
    for label, tree in _stage9_trees(repository_root).items():
        violations.extend(_denied_root_violations(tree, label))
    assert violations == []
    assert _DENIED_ROOTS.isdisjoint(_NEW_PACKAGES)
    # Several denied roots are legitimate elsewhere in the tree (Stage 7 and 8
    # importers), so the denial is per module, not a tree-wide allowlist change.
    assert {"threading", "asyncio", "ctypes", "queue", "subprocess", "types"} <= (
        _ALLOWED_IMPORT_ROOTS
    )


def test_no_new_class_carries_the_raw_token_annotation(repository_root: Path) -> None:
    found: list[tuple[str, str, str]] = []
    for label, tree in _stage9_trees(repository_root).items():
        found.extend(_attempt_token_fields(tree, label))
    assert found == []


def test_no_new_module_names_a_bare_forbidden_identifier(repository_root: Path) -> None:
    violations: list[str] = []
    for label, tree in _stage9_trees(repository_root).items():
        violations.extend(_bare_identifier_violations(tree, label))
    assert violations == []


def test_no_pickle_marshal_or_eval_in_new_modules(repository_root: Path) -> None:
    violations: list[str] = []
    for label, tree in _stage9_trees(repository_root).items():
        violations.extend(_dynamic_code_violations(tree, label))
    assert violations == []
    assert _DYNAMIC_CODE_ROOTS.isdisjoint(_ALLOWED_IMPORT_ROOTS)


def test_each_released_name_is_defined_once_and_the_deferred_names_nowhere(
    repository_root: Path,
) -> None:
    """Plan section 2.6 (deferred-definition guard), the excluded branch: twenty
    released, thirteen remaining, and the two sets are disjoint."""
    assert len(_RELEASED_DEFINITIONS) == 20
    assert set(_RELEASED_DEFINITIONS).isdisjoint(_DEFERRED_DEFINITIONS)
    assert len(_DEFERRED_DEFINITIONS) == 13
    assert set(_RELEASED_DEFINITIONS.values()) <= set(STAGE9_SOURCE_FILES)
    definers = _definers(repository_root, _RELEASED_DEFINITIONS)
    assert definers == {
        name: [module] for name, module in sorted(_RELEASED_DEFINITIONS.items())
    }
    deferred = _definers(repository_root, _DEFERRED_DEFINITIONS)
    assert deferred == {name: [] for name in sorted(_DEFERRED_DEFINITIONS)}


def test_the_hashing_profile_tail_is_the_eight_stage_nine_profiles() -> None:
    assert len(HashingProfile) == 20
    assert tuple(member.name for member in HashingProfile)[12:] == (
        _STAGE9_HASHING_PROFILES
    )
    for name in _STAGE9_HASHING_PROFILES:
        stem = name.lower().removesuffix("_v1").replace("_", "-")
        assert HashingProfile[name].value == f"{stem}/v1"
    assert len({member.value for member in HashingProfile}) == 20


def test_the_stage_nine_schema_entries_hold_positions_35_to_47_with_digests(
    repository_root: Path,
) -> None:
    """Plan section 2.6 (schema registry), the excluded branch: thirteen entries at
    35-47, 48 in all, each committed file hashed against the digest literal of
    ``tests/unit/test_schema_registry.py`` (declared reading 3)."""
    paths = tuple(
        definition.relative_path.as_posix() for definition in SCHEMA_DEFINITIONS
    )
    assert len(paths) == 48
    assert paths[35:48] == _STAGE9_SCHEMA_PATHS
    assert paths[35:] == _STAGE9_SCHEMA_PATHS
    assert len(_STAGE9_SCHEMA_PATHS) == 13
    assert len(sorted((repository_root / "schemas").rglob("*.schema.json"))) == 48
    digests = _digest_literal(repository_root)
    assert tuple(digests) == _STAGE9_SCHEMA_PATHS
    assert len(set(digests.values())) == 13
    mismatches: list[str] = []
    for name, expected in digests.items():
        assert len(expected) == 64, name
        assert set(expected) <= set("0123456789abcdef"), name
        actual = _sha256_of(repository_root / "schemas" / name)
        if actual != expected:
            mismatches.append(f"{name}: committed {actual}, pinned {expected}")
    assert not mismatches, "\n".join(mismatches)


def test_the_migration_head_is_the_stage_nine_revision(repository_root: Path) -> None:
    assert expected_head() == _STAGE9_REVISION
    versions = _source_path(repository_root, _VERSIONS_DIRECTORY)
    assert sorted(path.name for path in versions.rglob("*.py")) == [
        "__init__.py",
        f"{_BASELINE_REVISION}.py",
        f"{_STAGE9_REVISION}.py",
    ]
    successor = _revision_bindings(versions / f"{_STAGE9_REVISION}.py")
    assert successor["revision"] == _STAGE9_REVISION
    assert successor["down_revision"] == _BASELINE_REVISION
    revision_module = f"{_VERSIONS_DIRECTORY}/{_STAGE9_REVISION}.py"
    assert revision_module in STAGE9_SOURCE_FILES


def test_the_audit_action_vocabulary_is_the_closed_set_of_twenty_five() -> None:
    assert tuple(member.name for member in AuditAction) == _AUDIT_ACTIONS
    assert tuple(member.value for member in AuditAction) == _AUDIT_ACTIONS
    assert len(AuditAction) == 25
    assert len(set(_AUDIT_ACTIONS)) == 25


def test_the_guard_module_imports_no_subprocess() -> None:
    """The thirteen-importer allowlist of the Stage 6 guard is closed; this module
    is not one of them and must not become one by accident."""
    assert "tests/safety/test_stage9_boundaries.py" not in _SUBPROCESS_IMPORTERS
    assert "subprocess" not in _imported_roots(_parse(Path(__file__)))


# --------------------------------------------------------------------------
# Status pins (plan section 2.6, Task 9)
# --------------------------------------------------------------------------


def test_the_roadmap_records_stage_nine_complete_and_stage_ten_not_started(
    repository_root: Path,
) -> None:
    roadmap = _read(repository_root, _ROADMAP)
    readme = _read(repository_root, _README)
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    assert _STAGE9_COMPLETION_ROW in roadmap
    assert _STAGE9_DEFERRED_ROW not in roadmap  # the deferred row is gone
    assert _STAGE10_DEFERRED_ROW in roadmap
    # The Stage 8 row's last clause now reads "Stage 9 complete".
    assert _STAGE8_COMPLETION_ROW in roadmap
    assert _STAGE8_COMPLETION_ROW.endswith("Stage 9 complete |")
    assert _STAGE9_ROADMAP_STATUS_LINE in roadmap
    assert _STAGE9_ROADMAP_PLAN_SENTENCE in roadmap
    assert f"**Approved detailed implementation plan:** `{STAGE9_PLAN}`." in roadmap
    assert f"**Planned detailed implementation plan:** `{STAGE9_PLAN}`." not in roadmap
    assert "Stage 9 not started" not in roadmap
    assert "Stage 9 has not started" not in readme
    assert "Stage 9 is not started" not in guide
    assert roadmap.count("Stage 10 not started") == 1
    assert "Stage 9 complete" in roadmap
    assert "Stages 1 through 9" in roadmap
    assert "Stages 1-9" in readme
    assert "**Status:** Project 1 Stages 1-9 complete" in readme
    assert _README_STAGE9_STATUS in readme
    assert _VERIFICATION_STAGE9_STATUS in guide
    assert _README_STAGE8_STATUS not in readme
    assert _VERIFICATION_STAGE8_STATUS not in guide
    assert "Stage 10 has not started." in readme
    assert "Stage 10 is not started." in guide
    # The hash rules: the Task 8 hash once in the roadmap and nowhere else, distinct
    # from every earlier implementation hash, each of which keeps the same rule.
    earlier = (
        STAGE4_IMPLEMENTATION_COMMIT,
        STAGE5_IMPLEMENTATION_COMMIT,
        STAGE6_IMPLEMENTATION_COMMIT,
        STAGE7_IMPLEMENTATION_COMMIT,
        STAGE8_IMPLEMENTATION_COMMIT,
    )
    assert STAGE9_IMPLEMENTATION_COMMIT not in earlier
    for commit in (STAGE9_IMPLEMENTATION_COMMIT, *earlier):
        assert roadmap.count(commit) == 1, commit
        assert readme.count(commit) == 0, commit
        assert guide.count(commit) == 0, commit
    for text in (roadmap, readme, guide):
        for claim in _LATER_STAGE_CLAIMS:
            assert claim not in text
    # The roadmap names "sandbox" only inside the Stage 7 exclusion list; README and
    # the guide never use the word, and only the pinned corpus qualification of the
    # guide may say "exhaustive" (the roadmap's Stage 5 row says it legitimately).
    assert "sandbox" not in readme.lower()
    assert "sandbox" not in guide.lower()
    assert "exhaustiv" not in readme.lower()
    guide_rest = guide.replace(_VERIFICATION_CORPUS_QUALIFICATION, "")
    assert "exhaustiv" not in guide_rest.lower()


def test_the_guide_records_the_stage_nine_focused_checks_and_evidence(
    repository_root: Path,
) -> None:
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    readme = _read(repository_root, _README)
    assert _VERIFICATION_STAGE9_FOCUSED_PROSE in guide
    for targets in _STAGE9_FOCUSED_TARGETS:
        assert _focused_command(targets) in guide
    assert _VERIFICATION_STAGE9_OBLIGATIONS in guide
    assert _REGISTER_HEADING in guide
    assert _CLOSED_REGISTRY_SENTENCE in guide
    assert "closed 35-file registry" not in guide
    assert _STAGE9_REVISION in guide
    assert _BASELINE_REVISION in guide
    assert "Stage 10" not in _VERIFICATION_STAGE9_FOCUSED_PROSE
    assert "exhaustiv" not in _VERIFICATION_STAGE9_OBLIGATIONS.lower()
    assert "sandbox" not in _VERIFICATION_STAGE9_OBLIGATIONS.lower()
    # README lists the thirteen Stage 9 schema paths and the closed count.
    assert _README_REGISTRY_SENTENCE in readme
    for name in _STAGE9_SCHEMA_PATHS:
        assert f"schemas/{name}" in readme, name
    assert "closed at **35** schemas" not in readme


# --------------------------------------------------------------------------
# Planted-violation controls
# --------------------------------------------------------------------------


def test_the_package_closure_scan_detects_a_foreign_import() -> None:
    clean = ast.parse(
        "from crypto_lab.domain.results import Result\n"
        "from crypto_lab.artifacts.models import ArtifactRef\n"
        "from .ownership import ArtifactOwnerRef\n"
    )
    allowed = ("domain", "artifacts")
    assert _package_closure_violations(clean, "artifacts/x.py", allowed) == []
    for source in (
        "from crypto_lab.audit.models import AuditEvent\n",
        "from crypto_lab.adapters.events import RunEvent\n",
        "import crypto_lab.persistence.schema\n",
        "from crypto_lab import experiments\n",
    ):
        violations = _package_closure_violations(
            ast.parse(source), "artifacts/x.py", allowed
        )
        assert violations != [], source


def test_the_new_package_scan_names_exactly_the_packages_reached() -> None:
    tree = ast.parse(
        "from crypto_lab.artifacts.models import ArtifactRef\n"
        "from crypto_lab.audit.sink import AuditSink\n"
        "from crypto_lab.domain.results import Result\n"
    )
    assert _new_package_imports(tree, "experiments/x.py") == _NEW_PACKAGES
    only_domain = ast.parse("from crypto_lab.domain.results import Result\n")
    assert _new_package_imports(only_domain, "experiments/x.py") == frozenset()


@pytest.mark.parametrize(
    "source",
    [
        "import os as operating_system\n",
        "from os import fstat\n",
        "import os\nimport os\n",
        "import os.path\n",
        "x = 1\n",
    ],
)
def test_the_os_import_scan_detects_each_shape(source: str) -> None:
    assert _os_import_violations(ast.parse(source), "p") != []


def test_the_os_scans_accept_the_reviewed_shape_and_see_a_third_attribute() -> None:
    reviewed = ast.parse("import os\nos.fstat(h)\nos.fsync(h)\n")
    assert _os_import_violations(reviewed, "p") == []
    assert _os_attribute_reads(reviewed) == _OS_ATTRIBUTES
    widened = ast.parse("import os\nos.fstat(h)\nos.fsync(h)\nos.remove(p)\n")
    assert _os_attribute_reads(widened) != _OS_ATTRIBUTES
    assert "remove" in _os_attribute_reads(widened)


@pytest.mark.parametrize(
    "source",
    [
        "import shutil\n",
        "from tempfile import mkdtemp\n",
        "import io\n",
        "import errno\n",
        "import logging\n",
        "from time import monotonic\n",
        "import secrets\n",
        "import subprocess\n",
        "from types import MappingProxyType\n",
    ],
)
def test_the_denied_root_scan_detects_each_root(source: str) -> None:
    assert _denied_root_violations(ast.parse(source), "p") != []


def test_the_denied_root_scan_allows_the_reviewed_roots() -> None:
    tree = ast.parse(
        "import os\nimport hashlib\nimport re\nimport json\n"
        "from pathlib import Path\nfrom collections.abc import Callable\n"
    )
    assert _denied_root_violations(tree, "p") == []


@pytest.mark.parametrize(
    "source",
    [
        "import pickle\n",
        "import marshal\n",
        "from shelve import open as shelf\n",
        "eval(text)\n",
        "exec(code)\n",
        "compile(source, 'x', 'exec')\n",
        "__import__('os')\n",
    ],
)
def test_the_dynamic_code_scan_detects_each_shape(source: str) -> None:
    assert _dynamic_code_violations(ast.parse(source), "p") != []


def test_the_dynamic_code_scan_allows_attribute_calls_and_plain_code() -> None:
    tree = ast.parse("import re\npattern = re.compile(text)\nvalue = json.loads(x)\n")
    assert _dynamic_code_violations(tree, "p") == []


def test_the_literal_extractor_reads_the_annotated_assignment_only() -> None:
    source = (
        "from typing import Final\n"
        'OTHER = {"a": "1"}\n'
        '_STAGE9_SHA256: Final[dict[str, str]] = {"x/y.json": ("ab" * 32)}\n'
    )
    # A parenthesized string is a constant; a repeated string is not a literal.
    with pytest.raises(ValueError, match="malformed node"):
        _literal_assignment(source, "_STAGE9_SHA256")
    plain = (
        "from typing import Final\n"
        '_STAGE9_SHA256: Final[dict[str, str]] = {"x/y.json": ("abc")}\n'
    )
    assert _literal_assignment(plain, "_STAGE9_SHA256") == {"x/y.json": "abc"}
    assert _literal_assignment('OTHER = {"a": "1"}\n', "OTHER") == {"a": "1"}
    with pytest.raises(AssertionError, match="no literal assignment to MISSING"):
        _literal_assignment("x = 1\n", "MISSING")
    with pytest.raises(AssertionError, match="no literal assignment to x"):
        _literal_assignment("x: int\n", "x")


def test_the_definer_scan_reports_every_module_that_defines_a_name(
    repository_root: Path,
) -> None:
    found = _definers(repository_root, ("ArtifactRef", "CanonicalOrder"))
    assert found == {"ArtifactRef": ["artifacts/models.py"], "CanonicalOrder": []}


def test_the_focused_commands_render_from_their_constants() -> None:
    assert _focused_command(("tests\\unit\\artifacts", "tests\\unit\\audit")) == (
        "powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-uv.ps1 "
        "pytest-focused -o addopts= tests\\unit\\artifacts tests\\unit\\audit -q"
    )
    assert len(_STAGE9_FOCUSED_TARGETS) == 6
    assert len(set(_STAGE9_FOCUSED_TARGETS)) == 6
