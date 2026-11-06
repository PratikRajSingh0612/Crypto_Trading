"""Enforce the Stage 8 persistence boundary and record Stage 8 completion.

Stage 8 plan section 2.6 and Task 8. The guard pins the fifteen Stage 8 source
modules (disjoint from the Stage 5, 6 and 7 sets), confines ``sqlalchemy`` and
``alembic`` to their named importers, pins the exact ``crypto_lab`` modules each
persistence module imports as a reviewed literal per module (never a package
prefix), proves the two registry ports import only ``domain`` and their own
package, denies the infrastructure roots, the raw-token annotation, the bare
identifiers and every deferred name inside persistence, proves the
``diagnostic_ids`` column is written only through the whole-row
command-invocation encode, pins the one Alembic head, pins every census value
the stage reconciled, and records the roadmap, README and guide status of a
complete Stage 8 with Stage 9 not started.

Declared readings:

- The persistence import allowlist is narrower than the plan header's
  dependency bullet: ``crypto_lab.experiments.supervision_lifecycle`` and
  ``crypto_lab.process_supervision.ports`` are named there but imported by no
  persistence module (the recorder satisfies ``DiagnosticRecorder``
  structurally), so neither is admitted. ``crypto_lab.adapters.events``,
  ``.limits`` and ``.vocabulary``, ``crypto_lab.artifacts.ownership``,
  ``crypto_lab.configuration.models``, ``.snapshot`` and ``.retry_policy``,
  ``crypto_lab.datasets`` (the package re-exports), ``.models``, ``.hashing`` and
  ``.ports``, ``crypto_lab.experiments.ports``, ``crypto_lab.adapters.ports``,
  ``crypto_lab.process_supervision.models`` and ``crypto_lab.strategy.versioning``
  and ``.ports`` are admitted module by module with the name each supplies
  (``_PERSISTENCE_IMPORTS``); no ``experiments`` service, ``capabilities``,
  ``cli`` or ``schema_registry`` module is admitted anywhere.
- The bare-identifier scan covers names, attributes, arguments, definitions,
  keywords and import aliases; the original name of an aliased import
  (``from alembic import context as migration_context``) is the library's, not a
  persistence identifier.
- The implementation hash lives in test constants and once in the roadmap; the
  README and the guide refer readers to the roadmap's checkpoint and carry no
  Stage 7 or Stage 8 hash (plan section 2.6; the user's Task 8 clarification).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Final

import pytest
from test_project_dependencies import (
    _EXPECTED_RUNTIME_REQUIREMENTS,
    _PROHIBITED_FAMILIES,
)
from test_stage3_boundaries import (
    _ALLOWED_IMPORT_ROOTS,
    _ALLOWED_SOURCE_FILES,
    _DEFERRED_DEFINITIONS,
    _EXPECTED_VERIFICATION_PROFILES,
    _README_STAGE8_STATUS,
    _VERIFICATION_STAGE8_STATUS,
    STAGE7_IMPLEMENTATION_COMMIT,
    STAGE8_IMPLEMENTATION_COMMIT,
    STAGE8_PLAN,
    _imported_roots,
    _source_files,
)
from test_stage5_boundaries import (
    _EXPECTED_READER_IMPLEMENTATIONS,
    _INFRASTRUCTURE_EXEMPTIONS,
    STAGE5_SOURCE_FILES,
    _imported_names,
    _module_package,
    _parse,
)
from test_stage6_boundaries import _SUBPROCESS_IMPORTERS, STAGE6_SOURCE_FILES
from test_stage7_boundaries import (
    _STAGE7_ROADMAP_ROW,
    _STAGE8_ROADMAP_ROW,
    STAGE7_SOURCE_FILES,
    _defined_names,
    _subprocess_importer_phrase,
)
from test_uv_launcher import _EXPECTED_OPERATIONS

from crypto_lab.domain.hashing import HashingProfile
from crypto_lab.persistence.migration_runner import expected_head
from crypto_lab.schema_registry import SCHEMA_DEFINITIONS

#: Plan section 2.6 (source-file allowlist): the fifteen paths Stage 8 added, in
#: the order of the table (Task 1, 2, 3, 4, 5).
STAGE8_SOURCE_FILES: Final[tuple[str, ...]] = (
    "persistence/database.py",
    "persistence/diagnostics.py",
    "persistence/schema.py",
    "persistence/migration_runner.py",
    "persistence/migrations/__init__.py",
    "persistence/migrations/env.py",
    "persistence/migrations/versions/__init__.py",
    "persistence/migrations/versions/r0001_stage8_baseline.py",
    "persistence/codecs.py",
    "persistence/registries.py",
    "datasets/ports.py",
    "strategy/ports.py",
    "persistence/unit_of_work.py",
    "persistence/repositories.py",
    "persistence/reconciliation_source.py",
)
#: The persistence package: the fifteen minus the two ports plus the pre-existing
#: package marker.
_PERSISTENCE_PACKAGE_INIT: Final = "persistence/__init__.py"
_PERSISTENCE_MODULES: Final[frozenset[str]] = frozenset(
    {path for path in STAGE8_SOURCE_FILES if path.startswith("persistence/")}
    | {_PERSISTENCE_PACKAGE_INIT}
)
_PORT_MODULES: Final[tuple[str, ...]] = ("datasets/ports.py", "strategy/ports.py")
#: Plan section 2.6 (import-root allowlist): the exact importer sets of the two
#: Stage 8 roots.
_SQLALCHEMY_IMPORTERS: Final[frozenset[str]] = frozenset(
    {
        "persistence/database.py",
        "persistence/schema.py",
        "persistence/migration_runner.py",
        "persistence/migrations/env.py",
        "persistence/migrations/versions/r0001_stage8_baseline.py",
        "persistence/registries.py",
        "persistence/unit_of_work.py",
        "persistence/repositories.py",
        "persistence/reconciliation_source.py",
    }
)
_ALEMBIC_IMPORTERS: Final[frozenset[str]] = frozenset(
    {
        "persistence/migration_runner.py",
        "persistence/migrations/env.py",
        "persistence/migrations/versions/r0001_stage8_baseline.py",
    }
)
_ROOT_CONFINEMENT: Final[dict[str, frozenset[str]]] = {
    "sqlalchemy": _SQLALCHEMY_IMPORTERS,
    "alembic": _ALEMBIC_IMPORTERS,
}
#: Plan section 2.6: the roots no persistence module may import (``sqlite3``
#: error codes are local integers read from the wrapped exception).
_PERSISTENCE_FORBIDDEN_ROOTS: Final[frozenset[str]] = frozenset(
    {
        "sqlite3",
        "os",
        "sys",
        "time",
        "types",
        "io",
        "shutil",
        "tempfile",
        "logging",
        "threading",
        "queue",
        "ctypes",
        "asyncio",
        "subprocess",
        "random",
        "secrets",
    }
)
#: The reviewed literal allowlist: for each persistence module, exactly the
#: ``crypto_lab`` modules it imports (``crypto_lab.`` elided). Justification per
#: non-domain, non-persistence module: ``adapters.events`` supplies ``RunEvent``
#: (the persisted sanitized event); ``adapters.limits`` ``MAX_SEQUENCE`` and
#: ``adapters.vocabulary`` ``ProtocolEventType`` (the ``run_events`` CHECKs);
#: ``adapters.ports`` ``CommandInvocationRepository`` (the port the unit of work
#: implements); ``artifacts.ownership`` the six owner variants and
#: ``artifact_owner_hash`` (the ``artifact_owners`` table); ``configuration.models``
#: ``DatabaseConfig``, ``ApplicationConfig`` and ``MAX_CONFIGURATION_BYTES``;
#: ``configuration.snapshot`` ``ConfigSnapshot`` (reading 22's frozen snapshot);
#: ``configuration.retry_policy`` ``retry_policy_from_config`` (plan 4.3.1 step d');
#: ``datasets`` the package's ``DatasetDataType`` and ``DatasetValidationStatus``
#: re-exports (the ``datasets`` CHECKs), ``datasets.models`` the two records,
#: ``datasets.hashing`` ``validate_dataset_identity`` and ``datasets.ports`` the
#: registry port; ``experiments.ports`` the five lifecycle ports and
#: ``RetryDecisionInsertOutcome``; ``process_supervision.models``
#: ``RunReconciliationFacts`` (the reconciliation source's return type);
#: ``strategy.versioning`` ``StrategyVersion`` and its profile version and
#: ``strategy.ports`` the registry port. No ``experiments`` service module, no
#: ``capabilities``, ``cli`` or ``schema_registry`` module, and no
#: ``experiments.supervision_lifecycle`` or ``process_supervision.ports`` module
#: is admitted.
_PERSISTENCE_IMPORTS: Final[dict[str, frozenset[str]]] = {
    "persistence/__init__.py": frozenset(),
    "persistence/codecs.py": frozenset(
        {
            "adapters.events",
            "artifacts.ownership",
            "datasets.models",
            "domain.canonical_json",
            "domain.command_invocation",
            "domain.descriptors",
            "domain.diagnostics",
            "domain.engine_run",
            "domain.experiment",
            "domain.hashing",
            "domain.ports",
            "domain.results",
            "domain.retry",
            "domain.time",
            "persistence.diagnostics",
            "strategy.versioning",
        }
    ),
    "persistence/database.py": frozenset(
        {
            "configuration.models",
            "domain.diagnostics",
            "domain.lifecycle",
            "domain.ports",
            "domain.results",
            "persistence.diagnostics",
        }
    ),
    "persistence/diagnostics.py": frozenset(
        {
            "domain.canonical_json",
            "domain.diagnostics",
            "domain.hashing",
            "domain.ports",
            "domain.results",
        }
    ),
    "persistence/migration_runner.py": frozenset(
        {
            "domain.diagnostics",
            "domain.ports",
            "domain.results",
            "persistence",
            "persistence.database",
            "persistence.diagnostics",
            "persistence.schema",
        }
    ),
    "persistence/migrations/__init__.py": frozenset(),
    "persistence/migrations/env.py": frozenset({"persistence"}),
    "persistence/migrations/versions/__init__.py": frozenset(),
    "persistence/migrations/versions/r0001_stage8_baseline.py": frozenset(
        {"persistence"}
    ),
    "persistence/reconciliation_source.py": frozenset(
        {
            "domain.command_invocation",
            "domain.diagnostics",
            "domain.identifiers",
            "domain.lifecycle",
            "domain.ports",
            "domain.results",
            "persistence.codecs",
            "persistence.database",
            "persistence.diagnostics",
            "persistence.schema",
            "process_supervision.models",
        }
    ),
    "persistence/registries.py": frozenset(
        {
            "artifacts.ownership",
            "configuration.snapshot",
            "datasets.hashing",
            "datasets.models",
            "domain.canonical_json",
            "domain.descriptors",
            "domain.diagnostics",
            "domain.identifiers",
            "domain.lifecycle",
            "domain.ports",
            "domain.results",
            "domain.versioning",
            "persistence.codecs",
            "persistence.database",
            "persistence.diagnostics",
            "persistence.schema",
            "strategy.versioning",
        }
    ),
    "persistence/repositories.py": frozenset(
        {
            "adapters.events",
            "configuration.models",
            "configuration.retry_policy",
            "domain.command_invocation",
            "domain.diagnostics",
            "domain.engine_run",
            "domain.experiment",
            "domain.identifiers",
            "domain.lifecycle",
            "domain.ports",
            "domain.results",
            "domain.retry",
            "experiments.ports",
            "persistence.codecs",
            "persistence.database",
            "persistence.diagnostics",
            "persistence.schema",
        }
    ),
    "persistence/schema.py": frozenset(
        {
            "adapters.limits",
            "adapters.vocabulary",
            "artifacts.ownership",
            "configuration.models",
            "datasets",
            "domain.base",
            "domain.command_invocation",
            "domain.descriptors",
            "domain.diagnostics",
            "domain.experiment",
            "domain.lifecycle",
            "domain.retry",
            "strategy.versioning",
        }
    ),
    "persistence/unit_of_work.py": frozenset(
        {
            "adapters.ports",
            "artifacts.ownership",
            "configuration.snapshot",
            "datasets.models",
            "datasets.ports",
            "domain.descriptors",
            "domain.diagnostics",
            "domain.identifiers",
            "domain.ports",
            "domain.results",
            "domain.versioning",
            "experiments.ports",
            "persistence.database",
            "persistence.diagnostics",
            "persistence.registries",
            "persistence.repositories",
            "strategy.ports",
            "strategy.versioning",
        }
    ),
}
#: The families persistence may reach at all (every allowlisted module falls
#: under one); the complement is denied wholesale so a planted import of an
#: ``experiments`` service, ``capabilities``, ``cli`` or ``schema_registry`` fails
#: twice: by the per-module equality and by this family check.
_PERSISTENCE_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "adapters.events",
        "adapters.limits",
        "adapters.ports",
        "adapters.vocabulary",
        "artifacts.ownership",
        "configuration.models",
        "configuration.retry_policy",
        "configuration.snapshot",
        "datasets",
        "datasets.hashing",
        "datasets.models",
        "datasets.ports",
        "domain",
        "experiments.ports",
        "persistence",
        "process_supervision.models",
        "strategy.ports",
        "strategy.versioning",
    }
)
#: The two registry ports: exactly their imports, and the packages they may not
#: reach (plan section 2.6, "Architecture closure").
_PORT_IMPORTS: Final[dict[str, frozenset[str]]] = {
    "datasets/ports.py": frozenset(
        {"datasets.models", "domain.identifiers", "domain.results"}
    ),
    "strategy/ports.py": frozenset(
        {"domain.identifiers", "domain.results", "strategy.versioning"}
    ),
}
_PROHIBITED_FOR_PORTS: Final[tuple[str, ...]] = (
    "crypto_lab.persistence",
    "crypto_lab.experiments",
    "crypto_lab.adapters",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.capabilities",
    "crypto_lab.artifacts",
    "crypto_lab.cli",
    "crypto_lab.schema_registry",
)
_FORBIDDEN_ANNOTATION: Final = "AttemptToken"
_BARE_FORBIDDEN_IDENTIFIERS: Final[frozenset[str]] = frozenset(
    {"context", "buffer", "note", "problem"}
)
_DIAGNOSTIC_IDS: Final = "diagnostic_ids"
_DIAGNOSTIC_IDS_TOKEN: Final = re.compile(r"\bdiagnostic_ids\b")
#: Plan 1.5 note 5: the column is written only through the whole-row encode of
#: the command-invocation repository. These modules may name it -- the codec
#: (encode/decode of the whole record), the mapped column and its CHECK, the
#: baseline revision's DDL that creates the column, the read-only consistency SQL
#: and the diagnostic reader's parameter name -- and no other persistence module
#: may: in particular ``repositories.py`` and ``unit_of_work.py`` never name it.
_DIAGNOSTIC_IDS_NAMERS: Final[frozenset[str]] = frozenset(
    {
        "persistence/codecs.py",
        "persistence/schema.py",
        "persistence/migrations/versions/r0001_stage8_baseline.py",
        "persistence/database.py",
        "persistence/registries.py",
    }
)
_COMMAND_INVOCATION_ENCODER: Final = "encode_command_invocation"
_BASELINE_REVISION: Final = "r0001_stage8_baseline"
_VERSIONS_DIRECTORY: Final = "persistence/migrations/versions"
_ROADMAP: Final = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
_VERIFICATION_GUIDE: Final = "docs/development/verification.md"
_README: Final = "README.md"
#: Plan section 2.6 (status pins): the Stage 8 completion row; the implementation
#: hash is the Task 7 commit, written once in the roadmap and nowhere else.
_STAGE8_COMPLETION_ROW: Final = (
    "| 8 — SQLite Persistence and Migrations | Approved and executed | "
    f"Implementation complete at `{STAGE8_IMPLEMENTATION_COMMIT}` | Complete; SQLite "
    "write-ahead-log persistence with foreign keys, `synchronous=FULL` and a "
    "bounded busy timeout, SQLAlchemy mappings separate from the canonical models, "
    "repositories and short units of work with revision compare-and-swap, the "
    "Alembic baseline migration `r0001_stage8_baseline` as the single head with the "
    "offline migration consistency check, durable retry decisions with their "
    "delay, invocation-scoped sanitized events, owner relations, and the "
    "persistence-side reconciliation source, with the Stage 5 two-slot flow and "
    "eight Stage 6 rows driven through the production supervisor over the SQLite "
    "database; no canonical schema was added and the closed 35-schema registry is "
    "preserved byte-identical; the Stage 8 boundary guard, the Stage 8 focused "
    "checks and status pins and this status were added by the separate Task 8 "
    "commit, which is not the implementation hash; verified offline on the "
    "complete verifier; GitNexus remains `DISABLED_WITH_EVIDENCE` with the manual "
    "source, reference, and diff fallback recorded; Stage 9 not started |"
)
_STAGE9_DEFERRED_ROW: Final = (
    "| 9 — Artifact Finalization, Recovery, Provenance, and Audit | Intentionally "
    f"deferred until Stages 6{chr(0x2013)}8 completion | Not started | Not evaluated |"
)
#: The guide's Stage 8 focused-check paragraph and the five plan 9.1 targets the
#: command lines are generated from.
_VERIFICATION_STAGE8_FOCUSED_PROSE: Final = "\n".join(
    (
        "Stage 8's focused targets are the following. `tests\\unit\\persistence`,",
        "`tests\\integration\\persistence`, "
        "`tests\\property\\test_persistence_codecs.py`,",
        "`tests\\persistence_support` and "
        "`tests\\safety\\test_stage8_boundaries.py` are new",
        "in Stage 8; `tests\\unit\\datasets`, `tests\\unit\\strategy`,",
        "`tests\\unit\\experiments\\test_port_contracts.py`, `tests\\safety`,",
        "`tests\\architecture` and `tests\\unit\\test_schema_registry.py` are "
        "older modules",
        "whose contract Stage 8 extended with the two registry ports, the SQLite "
        "side of",
        "the shared port contracts and the Stage 8 boundary guard; the registry "
        "stays at",
        "35 schemas and the relational schema has one Alembic head.",
    )
)
_STAGE8_FOCUSED_TARGETS: Final[tuple[tuple[str, ...], ...]] = (
    ("tests\\unit\\persistence",),
    ("tests\\integration\\persistence",),
    (
        "tests\\property\\test_persistence_codecs.py",
        "tests\\unit\\datasets",
        "tests\\unit\\strategy",
    ),
    (
        "tests\\unit\\experiments\\test_port_contracts.py",
        "tests\\safety",
        "tests\\architecture",
    ),
    (
        "tests\\safety\\test_stage8_boundaries.py",
        "tests\\unit\\test_schema_registry.py",
    ),
)
_FOCUSED_COMMAND_PREFIX: Final = (
    "powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-uv.ps1 "
    "pytest-focused -o addopts= "
)
#: The guide's subprocess-importer sentence, closed against the current census
#: now that the containment literal has advanced; the deferred wording retires.
_SUBPROCESS_IMPORTER_PARENTHETICAL: Final = (
    " (the ten of Stage 6, the Stage 7 fake\nscript and the Stage 8 "
    "interrupted-writer test)"
)
_RETIRED_SUBPROCESS_IMPORTER_PARENTHETICAL: Final = (
    "the persistence interrupted-writer test"
)
#: The guide's recorded Stage 8 evidence and limitations, byte-exact including
#: its hard wrapping; the completion wording cannot be widened by deleting them.
_VERIFICATION_STAGE8_LIMITATIONS: Final = "\n".join(
    (
        "The Stage 8 evidence is recorded with its limits rather than rounded up. Two",
        "accepted design limitations: the diagnostic reference columns carry no "
        "foreign",
        "key, because the semantic-outcome operation mints diagnostics inside the",
        "transaction that references them, so the caller records the returned",
        "diagnostics afterwards and the integration flows prove zero dangling",
        "references at the end of every flow; and under the deferred-transaction model",
        "an unrelated commit between a transaction's first read and its first write is",
        "refused as a stale snapshot, the operation driver reruns once, and two such",
        "interleavings in a row surface as a bounded "
        "`PERSISTENCE.CONCURRENCY_CONFLICT`",
        "to a caller that already treats it as a lost swap. Two race cases are "
        "proven in",
        "a corrected form: the successor-versus-aggregation race cannot compete as",
        "first written, because an allowed successor pending on the slot's latest",
        "attempt leaves the classifier non-terminal, so its measured half is the",
        "non-competition and its other half uses a labelled compare-and-swap winner;",
        "and the read-set case's concurrent mover is the persistence-owned snapshot",
        "freeze of the experiment row, which changes no revision. A member write that",
        "fails fatally poisons its owning transaction logically at once, while the",
        "physical rollback and connection release happen through `commit()`,",
        "`rollback()` or the context cleanup, never eagerly inside the member. Three",
        "scoped production corrections landed between Task 6 and Task 7 and are part "
        "of",
        "the Stage 8 history (commits `b174d1decf89b1c337d84bd75dd520ffa0ef9709`,",
        "`4f71171ba14a89dc6fd64a10de1ec045c37b5f1b` and",
        "`dbb5535830dd190d0fcf376165022c54377c71dc`): closing a transaction after a",
        "member write failure, translating driver failures during reads into stable",
        "`Failure` results instead of exceptions or empty answers, and preserving "
        "those",
        "reader failures through the invocation services, the last of which edited the",
        "Stage 5 module `experiments/invocation_service.py`. The interrupted-writer "
        "case",
        "kills a child process mid-transaction and reopens the file with `quick_check`",
        "`ok`; it is process-interruption evidence, not a power-loss or "
        "storage-hardware",
        "proof. Two observations stay open rather than closed by a later passing "
        "run: a",
        "PowerShell helper used by one launcher test timed out under foreign host "
        "load,",
        "and one reopen in the interrupted-writer case once failed with",
        "`SQLITE_IOERR_TRUNCATE`; neither cause is established. Two readings of the",
        "Stage 8 plan were taken in the Task 7 tests and are recorded here: the",
        "process-timeout row follows the committed Stage 7 contract, so a pre-handoff",
        "timeout records `PROCESS.START_TIMED_OUT` with no native exit and a removed",
        "command root while a timeout after the running handoff records",
        "`PROCESS.RUN_TIMED_OUT` with the killed child's exit; and the durable "
        "two-slot",
        "flow seeds its availability observations through the writer exactly as the",
        "Stage 5 flow seeds them, because it runs no describe command that could mint",
        "one.",
    )
)
_LATER_STAGE_CLAIMS: Final[tuple[str, ...]] = (
    "Stage 9 has started",
    "Stage 9 is complete",
    "Stage 9 complete",
    "Stages 1-9",
    "Stages 1 through 9",
)


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def _read(repository_root: Path, relative: str) -> str:
    return (repository_root / relative).read_text(encoding="utf-8")


def _source_path(repository_root: Path, label: str) -> Path:
    return repository_root / "src/crypto_lab" / label


def _label(repository_root: Path, path: Path) -> str:
    return path.relative_to(repository_root / "src/crypto_lab").as_posix()


def _crypto_lab_imports(tree: ast.AST, label: str) -> frozenset[str]:
    """Every ``crypto_lab`` module the module imports, with the prefix elided."""
    names = _imported_names(tree, _module_package(label))
    return frozenset(
        name.removeprefix("crypto_lab.")
        for name in names
        if name == "crypto_lab" or name.startswith("crypto_lab.")
    )


def _import_allowlist_violations(
    tree: ast.AST, label: str, allowed: frozenset[str]
) -> list[str]:
    """The per-module equality pin: extra and missing imports are both violations."""
    actual = _crypto_lab_imports(tree, label)
    violations = [
        f"{label}: unlisted import crypto_lab.{name}"
        for name in sorted(actual - allowed)
    ]
    violations.extend(
        f"{label}: listed import crypto_lab.{name} is gone"
        for name in sorted(allowed - actual)
    )
    return violations


def _family_violations(imports: Iterable[str], label: str) -> list[str]:
    violations: list[str] = []
    for name in sorted(imports):
        if not any(
            name == family or name.startswith(f"{family}.")
            for family in _PERSISTENCE_FAMILIES
        ):
            violations.append(f"{label}: import crypto_lab.{name} outside every family")
    return violations


def _confinement_violations(
    roots_by_module: dict[str, frozenset[str]], root: str, importers: frozenset[str]
) -> list[str]:
    violations: list[str] = []
    for label in sorted(roots_by_module):
        imports = root in roots_by_module[label]
        if imports and label not in importers:
            violations.append(f"{label}: stray {root} importer")
        if not imports and label in importers:
            violations.append(f"{label}: lost {root} import")
    return violations


def _forbidden_root_violations(tree: ast.AST, label: str) -> list[str]:
    return [
        f"{label}: forbidden root {root}"
        for root in sorted(set(_imported_roots(tree)) & _PERSISTENCE_FORBIDDEN_ROOTS)
    ]


def _raw_token_violations(tree: ast.AST, label: str) -> list[str]:
    """``AttemptToken`` as a name, an attribute or inside a string annotation."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == _FORBIDDEN_ANNOTATION:
            violations.append(f"{label}:{node.lineno}: AttemptToken name")
        elif isinstance(node, ast.Attribute) and node.attr == _FORBIDDEN_ANNOTATION:
            violations.append(f"{label}:{node.lineno}: AttemptToken attribute")
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and re.search(r"\bAttemptToken\b", node.value) is not None
        ):
            # A string annotation or a docstring alike: the word belongs to the
            # four reviewed carriers, not to persistence.
            violations.append(f"{label}:{node.lineno}: AttemptToken in a string")
    return violations


def _bare_identifier_violations(tree: ast.AST, label: str) -> list[str]:
    """Names, attributes, arguments, definitions, keywords and import aliases."""
    violations: list[str] = []
    for node in ast.walk(tree):
        found: str | None = None
        if isinstance(node, ast.Name):
            found = node.id
        elif isinstance(node, ast.Attribute):
            found = node.attr
        elif isinstance(node, ast.arg):
            found = node.arg
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            found = node.name
        elif isinstance(node, ast.keyword):
            found = node.arg
        elif isinstance(node, ast.alias):
            found = node.asname
        if found in _BARE_FORBIDDEN_IDENTIFIERS:
            line = getattr(node, "lineno", 0)
            violations.append(f"{label}:{line}: bare identifier {found}")
    return violations


def _deferred_name_violations(tree: ast.AST, label: str) -> list[str]:
    # Stage 9 plan section 2.6 (Task 1): the Stage 7 `_STAGE8_AND_LATER_NAMES` literal
    # retired with the first released finalization names; the Stage 3 set alone is
    # the deferred authority.
    defined = _defined_names(tree)
    deferred = set(_DEFERRED_DEFINITIONS)
    return [
        f"{label}: defines deferred name {name}" for name in sorted(defined & deferred)
    ]


def _is_sqlalchemy_write(call: ast.Call) -> bool:
    """Is this ``.values(...)`` call chained onto an ``insert(...)`` or
    ``update(...)`` construct (rather than, say, a mapping's ``.values()``)?"""
    node: ast.expr = call.func
    while True:
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("insert", "update"):
                return True
            node = node.func
        else:
            return False


def _values_call_violations(tree: ast.AST, label: str) -> list[str]:
    """Every SQLAlchemy ``.values(...)`` call writes a whole encoded row: exactly
    one ``**`` splat of a name or of an ``encode_*`` call, never a column keyword."""
    violations: list[str] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "values"
            and _is_sqlalchemy_write(node)
        ):
            continue
        if node.args or len(node.keywords) != 1 or node.keywords[0].arg is not None:
            violations.append(f"{label}:{node.lineno}: values() sets columns by name")
            continue
        splat = node.keywords[0].value
        whole_row = isinstance(splat, ast.Name) or (
            isinstance(splat, ast.Call)
            and isinstance(splat.func, ast.Name)
            and splat.func.id.startswith("encode_")
        )
        if not whole_row:
            violations.append(f"{label}:{node.lineno}: values() splats a literal")
    return violations


def _port_direction_violations(
    tree: ast.AST, label: str, prohibited: Iterable[str]
) -> list[str]:
    violations: list[str] = []
    for name in _imported_names(tree, _module_package(label)):
        for package in prohibited:
            if name == package or name.startswith(f"{package}."):
                violations.append(f"{label}: prohibited import {name}")
    return violations


def _roots_by_module(repository_root: Path) -> dict[str, frozenset[str]]:
    return {
        _label(repository_root, path): frozenset(_imported_roots(_parse(path)))
        for path in _source_files(repository_root)
    }


def _focused_command(targets: tuple[str, ...]) -> str:
    return f"{_FOCUSED_COMMAND_PREFIX}{' '.join(targets)} -q"


def _verifier_step_lines() -> tuple[str, ...]:
    """The guide's numbered complete-verification list, generated from the Stage 3
    guard's profile tuple plus the direct Git step."""
    profiles = [
        f"launcher `{profile[0]}`" for profile in _EXPECTED_VERIFICATION_PROFILES
    ]
    steps = [*profiles, "direct `git diff --check`"]
    return tuple(f"{index}. {step}" for index, step in enumerate(steps, start=1))


# --------------------------------------------------------------------------
# Source-tree facts
# --------------------------------------------------------------------------


def test_the_stage_eight_source_files_are_exactly_the_fifteen_plan_paths(
    repository_root: Path,
) -> None:
    assert len(STAGE8_SOURCE_FILES) == 15
    assert len(set(STAGE8_SOURCE_FILES)) == 15
    assert set(STAGE8_SOURCE_FILES) <= _ALLOWED_SOURCE_FILES
    for earlier in (STAGE5_SOURCE_FILES, STAGE6_SOURCE_FILES, STAGE7_SOURCE_FILES):
        assert set(STAGE8_SOURCE_FILES).isdisjoint(earlier)
    for relative_path in STAGE8_SOURCE_FILES:
        assert _source_path(repository_root, relative_path).is_file()
    assert _PERSISTENCE_PACKAGE_INIT in _ALLOWED_SOURCE_FILES
    assert _PERSISTENCE_PACKAGE_INIT not in STAGE8_SOURCE_FILES
    # The whole inventory: 95 at the planning base plus the fifteen, plus the five
    # artifact contract modules of Stage 9 Task 1 and the five audit modules and
    # the metric module of Stage 9 Task 2 (Stage 9 plan section 2.6).
    assert len(_ALLOWED_SOURCE_FILES) == 121
    assert len(_source_files(repository_root)) == 121
    on_disk = {
        _label(repository_root, path)
        for path in _source_files(repository_root)
        if path.name != "__init__.py" or path.parent.name in ("migrations", "versions")
    }
    assert set(STAGE8_SOURCE_FILES) <= on_disk


def test_each_stage_eight_import_root_is_confined_to_its_named_modules(
    repository_root: Path,
) -> None:
    roots_by_module = _roots_by_module(repository_root)
    assert set(roots_by_module) == _ALLOWED_SOURCE_FILES
    violations: list[str] = []
    for root, importers in _ROOT_CONFINEMENT.items():
        assert root in _ALLOWED_IMPORT_ROOTS
        assert importers <= _PERSISTENCE_MODULES
        violations.extend(_confinement_violations(roots_by_module, root, importers))
    assert violations == []
    assert len(_SQLALCHEMY_IMPORTERS) == 9
    assert len(_ALEMBIC_IMPORTERS) == 3
    assert _ALEMBIC_IMPORTERS < _SQLALCHEMY_IMPORTERS
    # Every exemption pair of the Stage 5 guard is one of these importers' roots.
    stage8_pairs = {
        (label, root) for root, labels in _ROOT_CONFINEMENT.items() for label in labels
    }
    assert stage8_pairs <= set(_INFRASTRUCTURE_EXEMPTIONS)
    assert len(_INFRASTRUCTURE_EXEMPTIONS) == len(stage8_pairs) + 1


def test_every_persistence_module_imports_exactly_its_listed_crypto_lab_modules(
    repository_root: Path,
) -> None:
    assert set(_PERSISTENCE_IMPORTS) == _PERSISTENCE_MODULES
    violations: list[str] = []
    for label, allowed in _PERSISTENCE_IMPORTS.items():
        tree = _parse(_source_path(repository_root, label))
        violations.extend(_import_allowlist_violations(tree, label, allowed))
        violations.extend(_family_violations(allowed, label))
    assert violations == []
    # The header bullet names two modules no persistence module imports; the
    # allowlist admits neither (a narrower pin than the plan's prose).
    everything = frozenset().union(*_PERSISTENCE_IMPORTS.values())
    assert "experiments.supervision_lifecycle" not in everything
    assert "process_supervision.ports" not in everything
    assert not any(
        name.startswith(("experiments.", "capabilities", "cli", "schema_registry"))
        and name != "experiments.ports"
        for name in everything
    )


def test_the_two_registry_ports_import_only_domain_and_their_own_package(
    repository_root: Path,
) -> None:
    violations: list[str] = []
    for label, allowed in _PORT_IMPORTS.items():
        tree = _parse(_source_path(repository_root, label))
        violations.extend(_import_allowlist_violations(tree, label, allowed))
        violations.extend(
            _port_direction_violations(tree, label, _PROHIBITED_FOR_PORTS)
        )
        own_package = label.split("/")[0]
        for name in _crypto_lab_imports(tree, label):
            assert name.startswith(("domain.", f"{own_package}.")), (label, name)
    assert violations == []
    # The dependency direction: persistence imports the ports; nothing outside
    # persistence imports persistence.
    for path in _source_files(repository_root):
        label = _label(repository_root, path)
        if label in _PERSISTENCE_MODULES:
            continue
        imports = _crypto_lab_imports(_parse(path), label)
        assert not any(
            name == "persistence" or name.startswith("persistence.") for name in imports
        ), label


def test_persistence_modules_import_no_forbidden_root(repository_root: Path) -> None:
    violations: list[str] = []
    for label in sorted(_PERSISTENCE_MODULES):
        violations.extend(
            _forbidden_root_violations(
                _parse(_source_path(repository_root, label)), label
            )
        )
    assert violations == []


def test_persistence_names_no_raw_token_bare_identifier_or_deferred_name(
    repository_root: Path,
) -> None:
    violations: list[str] = []
    for label in sorted(_PERSISTENCE_MODULES | set(_PORT_MODULES)):
        tree = _parse(_source_path(repository_root, label))
        violations.extend(_raw_token_violations(tree, label))
        violations.extend(_bare_identifier_violations(tree, label))
        violations.extend(_deferred_name_violations(tree, label))
    assert violations == []
    # The one released name is defined exactly once, in its port module.
    assert "DatasetRepository" not in _DEFERRED_DEFINITIONS
    definers = [
        label
        for label in sorted(_PERSISTENCE_MODULES | set(_PORT_MODULES))
        if "DatasetRepository"
        in _defined_names(_parse(_source_path(repository_root, label)))
    ]
    assert definers == ["datasets/ports.py"]
    # Stage 9 plan section 2.6 (Task 1): 33 -> 22; the `<=` pin over the retired
    # Stage 7 literal is replaced by the Stage 3 guard's released-names positive.
    # Task 2: 22 -> 19 (`AuditEvent`, `AuditSink`, `MetricValue`).
    assert len(_DEFERRED_DEFINITIONS) == 19


def test_diagnostic_ids_are_written_only_through_the_whole_row_encode(
    repository_root: Path,
) -> None:
    """Plan 1.5 note 5: no persistence write path touches ``diagnostic_ids``
    outside the mapped compare-and-swap of the command-invocation repository."""
    namers = {
        label
        for label in sorted(_PERSISTENCE_MODULES)
        if _DIAGNOSTIC_IDS_TOKEN.search(
            _source_path(repository_root, label).read_text(encoding="utf-8")
        )
    }
    assert namers == _DIAGNOSTIC_IDS_NAMERS
    repositories = _parse(_source_path(repository_root, "persistence/repositories.py"))
    assert _values_call_violations(repositories, "persistence/repositories.py") == []
    encoder_calls = [
        node
        for node in ast.walk(repositories)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == _COMMAND_INVOCATION_ENCODER
    ]
    # The insert of ``add`` and the update of ``compare_and_swap``: nothing else.
    assert len(encoder_calls) == 2
    unit_of_work = _parse(_source_path(repository_root, "persistence/unit_of_work.py"))
    assert _values_call_violations(unit_of_work, "persistence/unit_of_work.py") == []


def test_the_script_directory_holds_exactly_the_baseline_head(
    repository_root: Path,
) -> None:
    assert expected_head() == _BASELINE_REVISION
    versions = _source_path(repository_root, _VERSIONS_DIRECTORY)
    assert sorted(path.name for path in versions.rglob("*.py")) == [
        "__init__.py",
        f"{_BASELINE_REVISION}.py",
    ]
    tree = _parse(versions / f"{_BASELINE_REVISION}.py")
    bindings: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                bindings[target.id] = node.value.value
    assert bindings["revision"] == _BASELINE_REVISION
    assert bindings["down_revision"] is None
    assert bindings["branch_labels"] is None
    assert bindings["depends_on"] is None


def test_every_reconciled_census_value_holds(repository_root: Path) -> None:
    """The countable items of plan 9.3 item 12, derived from the guards' own
    constants and the tree; the seven live mutation cases and the four digest
    blocks stay pinned by their owning tests (the Stage 3 guard and
    ``tests/unit/test_schema_registry.py``)."""
    # Stage 9 plan section 2.6, Task 1: paths 110 -> 115, deferred names 33 -> 22,
    # registry and files 35 -> 43, hashing profiles 12 -> 17; Task 2: paths -> 121,
    # deferred names -> 19, registry and files -> 46, profiles -> 18; the rest is
    # unchanged.
    assert len(_ALLOWED_SOURCE_FILES) == 121
    assert len(_ALLOWED_IMPORT_ROOTS) == 29
    assert len(_DEFERRED_DEFINITIONS) == 19
    assert len(_INFRASTRUCTURE_EXEMPTIONS) == 13
    assert len(_EXPECTED_READER_IMPLEMENTATIONS) == 5
    assert len(_SUBPROCESS_IMPORTERS) == 12
    assert len(_EXPECTED_RUNTIME_REQUIREMENTS) == 4
    assert len(_PROHIBITED_FAMILIES) == 27
    assert len(_EXPECTED_OPERATIONS) == 21
    assert len(_EXPECTED_VERIFICATION_PROFILES) == 10
    assert len(_verifier_step_lines()) == 11
    assert len(SCHEMA_DEFINITIONS) == 46
    assert len(sorted((repository_root / "schemas").rglob("*.schema.json"))) == 46
    assert len(HashingProfile) == 18


# --------------------------------------------------------------------------
# Status pins (plan section 2.6, Task 8)
# --------------------------------------------------------------------------


def test_the_roadmap_records_stage_eight_complete_and_stage_nine_not_started(
    repository_root: Path,
) -> None:
    roadmap = _read(repository_root, _ROADMAP)
    readme = _read(repository_root, _README)
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    assert _STAGE8_COMPLETION_ROW in roadmap
    assert _STAGE8_ROADMAP_ROW not in roadmap  # the deferred row is gone
    assert _STAGE9_DEFERRED_ROW in roadmap
    assert (
        _STAGE7_ROADMAP_ROW in roadmap
    )  # its last clause now reads "Stage 8 complete"
    assert _STAGE7_ROADMAP_ROW.endswith("Stage 8 complete |")
    assert f"**Approved detailed implementation plan:** `{STAGE8_PLAN}`." in roadmap
    assert f"**Planned detailed implementation plan:** `{STAGE8_PLAN}`." not in roadmap
    assert "Stage 8 not started" not in roadmap
    assert "Stage 8 has not started" not in readme
    assert "Stage 8 is not started" not in guide
    assert "Stage 8 complete" in roadmap
    assert "Stages 1 through 8" in roadmap
    assert "Stages 1-8" in readme
    assert _README_STAGE8_STATUS in readme
    assert _VERIFICATION_STAGE8_STATUS in guide
    # The hash rules: the Task 7 hash once in the roadmap and nowhere else; the
    # Stage 7 hash likewise, now that it has left README and the guide.
    assert roadmap.count(STAGE8_IMPLEMENTATION_COMMIT) == 1
    assert readme.count(STAGE8_IMPLEMENTATION_COMMIT) == 0
    assert guide.count(STAGE8_IMPLEMENTATION_COMMIT) == 0
    assert roadmap.count(STAGE7_IMPLEMENTATION_COMMIT) == 1
    assert readme.count(STAGE7_IMPLEMENTATION_COMMIT) == 0
    assert guide.count(STAGE7_IMPLEMENTATION_COMMIT) == 0
    for text in (roadmap, readme, guide):
        for claim in _LATER_STAGE_CLAIMS:
            assert claim not in text
    # The roadmap names "sandbox" only inside the Stage 7 exclusion list; README and
    # the guide never use the word (the Stage 7 guard pins the same rule).
    assert "sandbox" not in readme.lower()
    assert "sandbox" not in guide.lower()
    assert "Stage 9 has not started." in readme
    assert "Stage 9 is not started." in guide


def test_the_guide_records_the_stage_eight_focused_checks_and_evidence(
    repository_root: Path,
) -> None:
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    assert _VERIFICATION_STAGE8_FOCUSED_PROSE in guide
    for targets in _STAGE8_FOCUSED_TARGETS:
        assert _focused_command(targets) in guide
    assert _VERIFICATION_STAGE8_LIMITATIONS in guide
    phrase = _subprocess_importer_phrase(len(_SUBPROCESS_IMPORTERS))
    assert f"{phrase}{_SUBPROCESS_IMPORTER_PARENTHETICAL}" in guide
    assert _RETIRED_SUBPROCESS_IMPORTER_PARENTHETICAL not in guide
    lines = _verifier_step_lines()
    positions = [guide.find(line) for line in lines]
    assert all(position >= 0 for position in positions), lines
    assert positions == sorted(positions)
    assert "migration-check" in guide
    assert _BASELINE_REVISION in guide
    assert "exhaustiv" not in _VERIFICATION_STAGE8_LIMITATIONS.lower()
    assert "Stage 9" not in _VERIFICATION_STAGE8_LIMITATIONS


# --------------------------------------------------------------------------
# Planted-violation controls
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "word"),
    [
        (
            "from crypto_lab.experiments.experiment_service import create_experiment\n",
            "unlisted",
        ),
        ("from crypto_lab.capabilities.vocabulary import Capability\n", "unlisted"),
        ("import crypto_lab.cli\n", "unlisted"),
        ("from crypto_lab import schema_registry\n", "unlisted"),
        ("from crypto_lab.experiments.supervision_lifecycle import X\n", "unlisted"),
    ],
)
def test_the_import_allowlist_rejects_an_extra_or_forbidden_module(
    source: str, word: str
) -> None:
    allowed = _PERSISTENCE_IMPORTS["persistence/database.py"]
    base = "\n".join(f"import crypto_lab.{name}" for name in sorted(allowed))
    tree = ast.parse(f"{base}\n{source}")
    violations = _import_allowlist_violations(tree, "persistence/database.py", allowed)
    assert violations
    assert all(word in item for item in violations)
    assert _family_violations(_crypto_lab_imports(tree, "persistence/database.py"), "d")


def test_the_import_allowlist_notices_a_lost_import_and_accepts_the_exact_set() -> None:
    allowed = _PERSISTENCE_IMPORTS["persistence/database.py"]
    exact = "\n".join(f"import crypto_lab.{name}" for name in sorted(allowed))
    assert _import_allowlist_violations(ast.parse(exact), "d", allowed) == []
    fewer = "\n".join(f"import crypto_lab.{name}" for name in sorted(allowed)[1:])
    violations = _import_allowlist_violations(ast.parse(fewer), "d", allowed)
    assert violations == [f"d: listed import crypto_lab.{sorted(allowed)[0]} is gone"]


def test_the_confinement_scan_detects_a_stray_importer_and_a_lost_import() -> None:
    roots = {label: frozenset({"sqlalchemy"}) for label in _SQLALCHEMY_IMPORTERS}
    assert _confinement_violations(roots, "sqlalchemy", _SQLALCHEMY_IMPORTERS) == []
    roots["experiments/ports.py"] = frozenset({"sqlalchemy"})
    assert _confinement_violations(roots, "sqlalchemy", _SQLALCHEMY_IMPORTERS) == [
        "experiments/ports.py: stray sqlalchemy importer"
    ]
    del roots["experiments/ports.py"]
    roots["persistence/schema.py"] = frozenset()
    assert _confinement_violations(roots, "sqlalchemy", _SQLALCHEMY_IMPORTERS) == [
        "persistence/schema.py: lost sqlalchemy import"
    ]


@pytest.mark.parametrize(
    "source",
    ["import sqlite3\n", "from os import path\n", "import time as clock\n"],
)
def test_the_forbidden_root_scan_detects_each_root(source: str) -> None:
    assert _forbidden_root_violations(ast.parse(source), "p") != []
    assert _forbidden_root_violations(ast.parse("import sqlalchemy\n"), "p") == []


def test_the_raw_token_scan_detects_the_annotation_and_allows_the_material() -> None:
    assert _raw_token_violations(ast.parse("token: AttemptToken\n"), "p") != []
    assert _raw_token_violations(ast.parse("x: 'AttemptToken | None'\n"), "p") != []
    assert _raw_token_violations(ast.parse("y = m.AttemptToken\n"), "p") != []
    assert _raw_token_violations(ast.parse("token: AttemptTokenMaterial\n"), "p") == []
    assert _raw_token_violations(ast.parse("h = attempt_token_hash(t)\n"), "p") == []


@pytest.mark.parametrize(
    "source",
    [
        "context = 1\n",
        "def f(buffer):\n    return buffer\n",
        "x = y.note\n",
        "class problem:\n    pass\n",
        "g(note=1)\n",
        "from alembic import x as context\n",
    ],
)
def test_the_bare_identifier_scan_detects_each_shape(source: str) -> None:
    assert _bare_identifier_violations(ast.parse(source), "p") != []


def test_the_bare_identifier_scan_allows_the_aliased_import() -> None:
    source = "from alembic import context as migration_context\nmigration_context.x\n"
    assert _bare_identifier_violations(ast.parse(source), "p") == []


def test_the_deferred_name_scan_detects_a_definition() -> None:
    assert _deferred_name_violations(
        ast.parse("class RunManifest:\n    pass\n"), "p"
    ) == ["p: defines deferred name RunManifest"]
    assert (
        _deferred_name_violations(ast.parse("class SqliteThing:\n    pass\n"), "p")
        == []
    )


@pytest.mark.parametrize(
    "source",
    [
        "update(Row).where(x).values(diagnostic_ids=x)\n",
        "insert(Row).values(**{'a': 1})\n",
        "insert(Row).values(row, **encoded)\n",
        "update(Row).values(**encoded, **other)\n",
    ],
)
def test_the_values_scan_detects_a_column_write(source: str) -> None:
    assert _values_call_violations(ast.parse(source), "p") != []


def test_the_values_scan_accepts_the_whole_row_encodes() -> None:
    source = (
        "insert(Row).values(**encode_command_invocation(record))\n"
        "update(Row).where(x).values(**encoded)\n"
        "insert(Row).values(**slot)\n"
        "for item in mapping.values():\n    pass\n"
    )
    assert _values_call_violations(ast.parse(source), "p") == []


def test_the_port_direction_scan_detects_a_persistence_import() -> None:
    source = "from crypto_lab.persistence.database import SqliteDatabase\n"
    assert _port_direction_violations(
        ast.parse(source), "datasets/ports.py", _PROHIBITED_FOR_PORTS
    ) == ["datasets/ports.py: prohibited import crypto_lab.persistence.database"]
    clean = "from crypto_lab.domain.results import Result\n"
    assert (
        _port_direction_violations(
            ast.parse(clean), "datasets/ports.py", _PROHIBITED_FOR_PORTS
        )
        == []
    )


def test_the_focused_command_and_step_lines_render_from_their_constants() -> None:
    assert _focused_command(("tests\\unit\\persistence",)) == (
        "powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-uv.ps1 "
        "pytest-focused -o addopts= tests\\unit\\persistence -q"
    )
    lines = _verifier_step_lines()
    assert lines[0] == "1. launcher `lock-check`"
    assert lines[6] == "7. launcher `migration-check`"
    assert lines[10] == "11. direct `git diff --check`"
