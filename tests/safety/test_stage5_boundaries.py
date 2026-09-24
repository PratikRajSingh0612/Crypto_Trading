"""Stage 5 source-level safety guards (Stage 5 plan Task 9, "Stage 5 safety guard").

The plan names six facts: no ``crypto_lab`` module imports ``sqlalchemy``,
``sqlite3``, ``alembic``, ``subprocess``, ``os.environ``, ``random``, ``secrets``,
``time`` or ``datetime.now``; no Stage 5 module reads the filesystem or the
environment at import time; ``crypto_lab.experiments`` and ``crypto_lab.adapters``
import none of the packages the section 27.1 table permits but Stage 5 excludes;
``tests/doubles`` is imported by no ``crypto_lab`` module; and no traversal logic
exists in any ``DiagnosticReader`` implementation. Every scan here is static and
AST-based, and every scan carries a planted-violation control, because a guard
that cannot fail is not a guard.

Declared readings, so nothing is inferred silently:

- The stdlib denylist matches the FIRST dotted component of every import
  (``_imported_roots`` from the Stage 3 guard), so the Stage 3 module
  ``crypto_lab.domain.time`` is legitimate and only the standard-library root
  ``time`` is forbidden. The whole-tree scans begin green and are load-bearing
  through their controls; ``os.environ`` is the Stage 3 environment scan reused.
  Stage 7 plan section 2.6 (Task 4) adds one label-keyed exemption,
  ``_INFRASTRUCTURE_EXEMPTIONS``: ``subprocess`` in
  ``process_supervision/windows_process.py``, the one ``Popen`` importer in ``src``.
  Stage 8 plan section 2.6 adds one ``(module, root)`` pair per persistence module
  that imports an infrastructure root, each in the task that first imports it
  (Task 1: ``sqlalchemy`` in ``persistence/database.py``; Task 2: ``sqlalchemy``
  in ``persistence/schema.py``, ``sqlalchemy`` and ``alembic`` in each of
  ``persistence/migration_runner.py``, ``persistence/migrations/env.py`` and
  ``persistence/migrations/versions/r0001_stage8_baseline.py``). Every other
  pair, the same root in any other module included, still fails, and each
  exempted module must really import its root.
- "Stage 5 module" means exactly the eighteen paths plan section 2.7 tabulates,
  pinned here as a literal so a widened set cannot pass by omission. "Reads the
  filesystem or the environment at import time" is discharged statically as a
  deliberate over-approximation -- none of the eighteen imports ``os``,
  ``pathlib``, ``importlib``, ``io``, ``sys``, ``shutil``, ``tempfile`` or ``glob``
  and none calls ``open`` -- while the behavioural half is already discharged by
  the fresh-import probe over ``PACKAGE_MODULES`` in
  ``tests/unit/test_package_layout.py``.
- The out-of-scope set is ``process_supervision``, ``artifacts``, ``datasets``,
  ``audit`` and ``strategy``: every package the dependency table permits the
  application layer that Stage 5 nevertheless does not touch. The architecture
  guard's ``experiments`` allowlist already excludes them, so both guards trip
  together; the separation the plan describes is recorded rather than real.
- A ``DiagnosticReader`` implementation is located structurally: any class under
  ``src/crypto_lab`` or ``tests`` that defines both ``get`` and ``get_many`` and is
  not the ``Protocol`` itself. "Traversal" is any attribute read of
  ``causal_diagnostic_ids``, any ``while`` loop, any call to ``self.get``,
  ``self.get_many`` or ``resolve_causal_closure``, or any ``for`` whose iterable
  is not the enclosing method's own parameter (directly or through one call on
  it). The double's ``get_many`` legitimately iterates its ``diagnostic_ids``
  argument, which is a primitive read, not a walk.
- "Single traversal owner" (plan 8.2) is two facts: every ``.get_many(`` call site
  under ``src/crypto_lab`` is in ``experiments/retry.py``, and every Load-context
  attribute read of ``causal_diagnostic_ids`` under ``src/crypto_lab`` outside the
  field's owner ``domain/diagnostics.py`` is in ``experiments/retry.py`` inside
  ``_has_cycle`` or ``resolve_causal_closure``. Keyword constructions, dict keys and
  parameter names are not reads.
"""

from __future__ import annotations

import ast
from importlib.util import resolve_name
from pathlib import Path
from typing import Final

import pytest
from test_stage3_boundaries import (
    _ALLOWED_SOURCE_FILES,
    _README_STAGE7_STATUS,
    _environment_access_violations,
    _import_aliases,
    _imported_roots,
    _resolved_qualified_name,
)

#: Plan section 2.7: the eighteen modules Stage 5 created, Task 1 through Task 8.
STAGE5_SOURCE_FILES: Final[tuple[str, ...]] = (
    "domain/lifecycle.py",
    "domain/ports.py",
    "domain/compatibility.py",
    "domain/experiment.py",
    "domain/retry.py",
    "configuration/retry_policy.py",
    "domain/command_invocation.py",
    "domain/engine_run.py",
    "domain/aggregation.py",
    "experiments/ports.py",
    "experiments/requests.py",
    "experiments/diagnostics.py",
    "experiments/experiment_service.py",
    "experiments/run_service.py",
    "experiments/invocation_service.py",
    "adapters/ports.py",
    "experiments/retry.py",
    "experiments/aggregation.py",
)
_INFRASTRUCTURE_ROOTS: Final = frozenset(
    {"sqlalchemy", "sqlite3", "alembic", "subprocess", "random", "secrets", "time"}
)
#: Stage 7 plan section 2.6 (Task 4): the one whole-block, label-keyed exemption from
#: the infrastructure scan -- the Windows process controller's ``subprocess`` import.
#: Keyed on the exact module label and root, so no sibling module, no other root in the
#: same module and no planted in-memory module is licensed by it.
_INFRASTRUCTURE_EXEMPTIONS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("process_supervision/windows_process.py", "subprocess"),
        ("persistence/database.py", "sqlalchemy"),
        ("persistence/schema.py", "sqlalchemy"),
        ("persistence/migration_runner.py", "sqlalchemy"),
        ("persistence/migration_runner.py", "alembic"),
        ("persistence/migrations/env.py", "sqlalchemy"),
        ("persistence/migrations/env.py", "alembic"),
        ("persistence/migrations/versions/r0001_stage8_baseline.py", "sqlalchemy"),
        ("persistence/migrations/versions/r0001_stage8_baseline.py", "alembic"),
        ("persistence/registries.py", "sqlalchemy"),
        ("persistence/repositories.py", "sqlalchemy"),
        ("persistence/unit_of_work.py", "sqlalchemy"),
    }
)
#: Resolved through the module's own import bindings, so ``from datetime import
#: datetime as dt; dt.now()`` and ``import datetime; datetime.date.today()`` both
#: resolve to a member of this set.
_AMBIENT_CLOCK_READS: Final = frozenset(
    {"datetime.datetime.now", "datetime.datetime.utcnow", "datetime.date.today"}
)
_FILESYSTEM_AND_ENVIRONMENT_ROOTS: Final = frozenset(
    {"os", "pathlib", "importlib", "io", "sys", "shutil", "tempfile", "glob"}
)
_TEST_DOUBLE_ROOTS: Final = frozenset({"doubles", "tests"})
_OUT_OF_SCOPE_PACKAGES: Final[tuple[str, ...]] = (
    "crypto_lab.process_supervision",
    "crypto_lab.artifacts",
    "crypto_lab.datasets",
    "crypto_lab.audit",
    "crypto_lab.strategy",
)
_STAGE5_APPLICATION_PACKAGES: Final[tuple[str, ...]] = ("experiments", "adapters")
_READER_METHODS: Final = frozenset({"get", "get_many"})
#: Every ``DiagnosticReader`` implementation in the tree, by ``path::class``.
_EXPECTED_READER_IMPLEMENTATIONS: Final = frozenset(
    {
        "src/crypto_lab/persistence/registries.py::SqliteDiagnosticReader",
        "tests/doubles/experiments.py::InMemoryDiagnosticReader",
        "tests/property/test_retry_decision_determinism.py::_RecordingReader",
        "tests/unit/experiments/test_retry_decision.py::_RecordingReader",
        "tests/unit/experiments/test_retry_decision.py::_FaultingDiagnostics",
    }
)
_TRAVERSAL_OWNER: Final = "experiments/retry.py"
_TRAVERSAL_OWNER_FUNCTIONS: Final = frozenset({"_has_cycle", "resolve_causal_closure"})
_FIELD_OWNER: Final = "domain/diagnostics.py"
_STAGE5_PLAN: Final = (
    "docs/superpowers/plans/2026-08-10-project-1-experiment-run-invocation-retry-"
    "aggregation-implementation-plan.md"
)
_ROADMAP: Final = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
_VERIFICATION_GUIDE: Final = "docs/development/verification.md"
#: The roadmap's deferred Stage 6 row, which Stage 5 completion left exactly as it
#: was and which Stage 6 completion retired (Stage 6 plan section 2.6); its
#: completion successor is pinned by ``tests/safety/test_stage6_boundaries.py``.
_STAGE6_ROADMAP_ROW: Final = (
    "| 6 — Adapter Protocol and Fake-Adapter Contract Harness | Intentionally "
    "deferred until Stages 3 and 5 completion | Not started | Not evaluated |"
)


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def _source_files(repository_root: Path) -> tuple[Path, ...]:
    return tuple(sorted((repository_root / "src/crypto_lab").rglob("*.py")))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _module_package(relative_path: str) -> str:
    """The dotted package a ``src/crypto_lab``-relative module belongs to."""
    parts = relative_path.removesuffix(".py").split("/")
    if parts[-1] != "__init__":
        parts = parts[:-1]
    return ".".join(("crypto_lab", *parts))


def _imported_names(tree: ast.AST, module_package: str) -> tuple[str, ...]:
    """Every absolute module name an import statement reaches, relative ones
    resolved against ``module_package`` and ``from crypto_lab import x`` expanded."""
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level > 0:
                base = resolve_name("." * node.level + base, module_package)
            if base == "crypto_lab":
                names.extend(f"crypto_lab.{alias.name}" for alias in node.names)
            else:
                names.append(base)
    return tuple(names)


def _infrastructure_violations(tree: ast.AST, label: str) -> list[str]:
    return [
        f"{label}: forbidden import root {root}"
        for root in _imported_roots(tree)
        if root in _INFRASTRUCTURE_ROOTS
        and (label, root) not in _INFRASTRUCTURE_EXEMPTIONS
    ]


def _ambient_clock_violations(tree: ast.AST, label: str) -> list[str]:
    aliases = _import_aliases(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            resolved = _resolved_qualified_name(node, aliases)
            if resolved in _AMBIENT_CLOCK_READS:
                violations.append(f"{label}:{node.lineno}: ambient clock {resolved}")
    return violations


def _filesystem_violations(tree: ast.AST, label: str) -> list[str]:
    violations = [
        f"{label}: filesystem or environment root {root}"
        for root in _imported_roots(tree)
        if root in _FILESYSTEM_AND_ENVIRONMENT_ROOTS
    ]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if (isinstance(target, ast.Name) and target.id == "open") or (
            isinstance(target, ast.Attribute) and target.attr == "open"
        ):
            violations.append(f"{label}:{node.lineno}: open() call")
    return violations


def _test_double_violations(tree: ast.AST, label: str) -> list[str]:
    return [
        f"{label}: test double import {root}"
        for root in _imported_roots(tree)
        if root in _TEST_DOUBLE_ROOTS
    ]


def _out_of_scope_violations(
    tree: ast.AST, label: str, module_package: str
) -> list[str]:
    violations: list[str] = []
    for name in _imported_names(tree, module_package):
        for package in _OUT_OF_SCOPE_PACKAGES:
            if name == package or name.startswith(f"{package}."):
                violations.append(f"{label}: out-of-scope import {name}")
    return violations


def _is_protocol_class(node: ast.ClassDef) -> bool:
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id == "Protocol":
            return True
        if isinstance(base, ast.Attribute) and base.attr == "Protocol":
            return True
    return False


def _reader_implementations(tree: ast.AST) -> tuple[ast.ClassDef, ...]:
    """Every class defining both ``get`` and ``get_many`` that is not the port."""
    found: list[ast.ClassDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or _is_protocol_class(node):
            continue
        methods = {
            item.name
            for item in node.body
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        if _READER_METHODS <= methods:
            found.append(node)
    return tuple(found)


def _parameter_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    arguments = function.args
    names = {
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return frozenset(names)


def _iterates_a_parameter(iterable: ast.expr, parameters: frozenset[str]) -> bool:
    if isinstance(iterable, ast.Name):
        return iterable.id in parameters
    if isinstance(iterable, ast.Call) and iterable.args:
        first = iterable.args[0]
        return isinstance(first, ast.Name) and first.id in parameters
    return False


def _traversal_violations(class_node: ast.ClassDef, label: str) -> list[str]:
    violations: list[str] = []
    for function in class_node.body:
        if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        parameters = _parameter_names(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.stmt | ast.expr):
                continue
            where = f"{label}.{function.name}:{node.lineno}"
            if isinstance(node, ast.Attribute) and node.attr == "causal_diagnostic_ids":
                violations.append(f"{where}: reads causal_diagnostic_ids")
            elif isinstance(node, ast.While):
                violations.append(f"{where}: while loop")
            elif isinstance(node, ast.For | ast.AsyncFor) and not _iterates_a_parameter(
                node.iter, parameters
            ):
                violations.append(f"{where}: loop over a non-parameter iterable")
            elif isinstance(node, ast.Call):
                target = node.func
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and target.attr in _READER_METHODS
                ):
                    violations.append(f"{where}: recursive self.{target.attr} call")
                if (
                    isinstance(target, ast.Name)
                    and target.id == "resolve_causal_closure"
                ):
                    violations.append(f"{where}: resolve_causal_closure call")
    return violations


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Map every node id to the innermost function name that encloses it."""
    owners: dict[int, str] = {}

    def visit(node: ast.AST, owner: str) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            owner = node.name
        owners[id(node)] = owner
        for child in ast.iter_child_nodes(node):
            visit(child, owner)

    visit(tree, "<module>")
    return owners


def _get_many_call_sites(tree: ast.AST) -> tuple[str, ...]:
    owners = _enclosing_functions(tree)
    return tuple(
        owners[id(node)]
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_many"
    )


def _causal_closure_reads(tree: ast.AST) -> tuple[str, ...]:
    owners = _enclosing_functions(tree)
    return tuple(
        owners[id(node)]
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr == "causal_diagnostic_ids"
        and isinstance(node.ctx, ast.Load)
    )


# --------------------------------------------------------------------------
# The repository assertions
# --------------------------------------------------------------------------


def test_the_stage_five_source_files_are_exactly_the_eighteen_plan_paths(
    repository_root: Path,
) -> None:
    assert len(STAGE5_SOURCE_FILES) == 18
    assert len(set(STAGE5_SOURCE_FILES)) == 18
    assert set(STAGE5_SOURCE_FILES) <= _ALLOWED_SOURCE_FILES
    for relative_path in STAGE5_SOURCE_FILES:
        assert (repository_root / "src/crypto_lab" / relative_path).is_file()


def test_no_source_module_imports_an_infrastructure_root(repository_root: Path) -> None:
    source = repository_root / "src/crypto_lab"
    violations: list[str] = []
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        violations.extend(_infrastructure_violations(_parse(path), label))
    assert violations == []


def test_no_source_module_reads_an_ambient_clock_or_the_environment(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    violations: list[str] = []
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        tree = _parse(path)
        violations.extend(_ambient_clock_violations(tree, label))
        violations.extend(_environment_access_violations(tree, label))
    assert violations == []


def test_stage_five_modules_touch_neither_filesystem_nor_environment(
    repository_root: Path,
) -> None:
    violations: list[str] = []
    for relative_path in STAGE5_SOURCE_FILES:
        tree = _parse(repository_root / "src/crypto_lab" / relative_path)
        violations.extend(_filesystem_violations(tree, relative_path))
    assert violations == []


def test_experiments_and_adapters_import_no_out_of_scope_package(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    violations: list[str] = []
    scanned = 0
    for package in _STAGE5_APPLICATION_PACKAGES:
        for path in sorted((source / package).rglob("*.py")):
            label = path.relative_to(source).as_posix()
            violations.extend(
                _out_of_scope_violations(_parse(path), label, _module_package(label))
            )
            scanned += 1
    assert violations == []
    assert scanned >= 12


def test_no_source_module_imports_the_test_doubles(repository_root: Path) -> None:
    source = repository_root / "src/crypto_lab"
    violations: list[str] = []
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        violations.extend(_test_double_violations(_parse(path), label))
    assert violations == []


def test_every_diagnostic_reader_implementation_is_traversal_free(
    repository_root: Path,
) -> None:
    """Plan 8.2: primitive reads only, in the double and in every test-local reader."""
    discovered: set[str] = set()
    violations: list[str] = []
    roots = (repository_root / "src/crypto_lab", repository_root / "tests")
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            label = path.relative_to(repository_root).as_posix()
            for class_node in _reader_implementations(_parse(path)):
                discovered.add(f"{label}::{class_node.name}")
                violations.extend(_traversal_violations(class_node, label))
    assert discovered == set(_EXPECTED_READER_IMPLEMENTATIONS)
    assert violations == []


def test_resolve_causal_closure_is_the_single_traversal_owner(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    call_sites: set[tuple[str, str]] = set()
    reads: set[tuple[str, str]] = set()
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        tree = _parse(path)
        call_sites.update((label, owner) for owner in _get_many_call_sites(tree))
        if label != _FIELD_OWNER:
            reads.update((label, owner) for owner in _causal_closure_reads(tree))
    assert call_sites == {(_TRAVERSAL_OWNER, "resolve_causal_closure")}
    assert reads == {(_TRAVERSAL_OWNER, name) for name in _TRAVERSAL_OWNER_FUNCTIONS}


def test_the_roadmap_records_stage_five_approved_and_stage_six_not_started(
    repository_root: Path,
) -> None:
    """The completion-status facts that plan section 2.7 does not tabulate.

    Section 2.7 is the single authority for every edit to a Stage 1-4 test file,
    so the untabulated pins live here, in the Task 9-owned guard: the roadmap's
    Stage 5 plan line is the approved form; the deferred Stage 6 row is gone
    (Stage 6 plan section 2.6: the positive became this negative, and the Stage 6
    completion row is pinned by the Stage 6 guard and the Stage 7 completion row
    by the Stage 7 guard, Stage 7 plan section 2.6); README no longer calls Stage 5
    pending and, outside its pinned Stage 7 status block, claims no stage later
    than Stage 8 (the Stage 8 containment itself is the Stage 3 guard's; the
    verification guide legitimately records Stage 7 and Stage 9 deferrals of
    frozen residuals, so only its Stage 5 pending phrase is denied here).
    """
    roadmap = (repository_root / _ROADMAP).read_text(encoding="utf-8")
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    guide = (repository_root / _VERIFICATION_GUIDE).read_text(encoding="utf-8")
    assert f"**Approved detailed implementation plan:** `{_STAGE5_PLAN}`." in roadmap
    assert f"**Planned detailed implementation plan:** `{_STAGE5_PLAN}`." not in roadmap
    assert _STAGE6_ROADMAP_ROW not in roadmap
    assert "Stage 5 has not started" not in readme
    assert "Stage 5 is not started" not in guide
    assert _README_STAGE7_STATUS in readme
    readme_rest = readme.replace(_README_STAGE7_STATUS, "")
    for later in ("Stage 8", "Stage 9", "Stage 10"):
        assert later not in readme_rest


# --------------------------------------------------------------------------
# Planted-violation controls
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import sqlalchemy\n",
        "import sqlite3\n",
        "from alembic import op\n",
        "import subprocess\n",
        "import random\n",
        "import secrets\n",
        "import time\n",
        "from time import monotonic\n",
    ],
)
def test_the_infrastructure_scan_detects_each_root(source: str) -> None:
    assert _infrastructure_violations(ast.parse(source), "probe.py") != []


@pytest.mark.parametrize(
    "source",
    [
        "from crypto_lab.domain.time import format_utc\n",
        "from datetime import UTC, datetime, timedelta\n",
        "import crypto_lab.domain.time\n",
    ],
)
def test_the_infrastructure_scan_allows_the_legitimate_shapes(source: str) -> None:
    assert _infrastructure_violations(ast.parse(source), "probe.py") == []


def test_each_infrastructure_exemption_licenses_exactly_its_pair(
    repository_root: Path,
) -> None:
    """The whole-block, label-keyed exemptions, iterated pair by pair.

    Stage 7 plan section 2.6 (Task 4) and Stage 8 plan section 2.6 (Tasks 1 to 3):
    exactly the reviewed ``(module, root)`` pairs are exempt and each licenses
    nothing else. The exempted module must really import its root, so a pair
    cannot outlive the import it licenses; every other denied root still fails in
    that module; the exempted root still fails in a sibling module; and a planted
    in-memory module labelled ``<package>/probe.py`` (no such repository file
    exists) still fails. The three Stage 7 controls stay -- ``time`` in the
    process controller, ``subprocess`` in ``windows_api.py``, the planted
    ``process_supervision/probe.py`` -- and Stage 8 adds their three mirrors:
    ``sqlalchemy`` in ``experiments/ports.py``, a planted ``persistence/probe.py``
    and ``time`` in ``persistence/database.py``.
    """
    assert _INFRASTRUCTURE_EXEMPTIONS == frozenset(
        {
            ("process_supervision/windows_process.py", "subprocess"),
            ("persistence/database.py", "sqlalchemy"),
            ("persistence/schema.py", "sqlalchemy"),
            ("persistence/migration_runner.py", "sqlalchemy"),
            ("persistence/migration_runner.py", "alembic"),
            ("persistence/migrations/env.py", "sqlalchemy"),
            ("persistence/migrations/env.py", "alembic"),
            ("persistence/migrations/versions/r0001_stage8_baseline.py", "sqlalchemy"),
            ("persistence/migrations/versions/r0001_stage8_baseline.py", "alembic"),
            ("persistence/registries.py", "sqlalchemy"),
            ("persistence/repositories.py", "sqlalchemy"),
            ("persistence/unit_of_work.py", "sqlalchemy"),
        }
    )
    source = repository_root / "src/crypto_lab"
    for module, root in sorted(_INFRASTRUCTURE_EXEMPTIONS):
        tree = _parse(source / module)
        assert root in _imported_roots(tree), (module, root)
        assert _infrastructure_violations(tree, module) == []
        # Every denied root the module holds no pair for still fails there (the
        # three Alembic modules hold two pairs each, ``sqlalchemy`` and ``alembic``).
        exempt_here = {
            pair_root
            for pair_module, pair_root in _INFRASTRUCTURE_EXEMPTIONS
            if pair_module == module
        }
        for other_root in sorted(_INFRASTRUCTURE_ROOTS - exempt_here):
            planted_root = ast.parse(f"import {other_root}\n")
            assert _infrastructure_violations(planted_root, module) != []
        planted = f"{module.partition('/')[0]}/probe.py"
        assert not (source / planted).exists()
        assert _infrastructure_violations(ast.parse(f"import {root}\n"), planted) != []
    controls = (
        ("import time\n", "process_supervision/windows_process.py"),
        ("import subprocess\n", "process_supervision/windows_api.py"),
        ("import subprocess\n", "process_supervision/probe.py"),
        ("import sqlalchemy\n", "experiments/ports.py"),
        ("import sqlalchemy\n", "persistence/probe.py"),
        ("import time\n", "persistence/database.py"),
    )
    for statement, label in controls:
        assert _infrastructure_violations(ast.parse(statement), label) != [], label


@pytest.mark.parametrize(
    "source",
    [
        "from datetime import datetime\ndatetime.now()\n",
        "from datetime import datetime as dt\ndt.utcnow()\n",
        "import datetime\ndatetime.datetime.now()\n",
        "import datetime\ndatetime.date.today()\n",
    ],
)
def test_the_ambient_clock_scan_detects_each_shape(source: str) -> None:
    assert _ambient_clock_violations(ast.parse(source), "probe.py") != []


def test_the_ambient_clock_scan_allows_an_injected_clock() -> None:
    source = "def f(clock):\n    return clock.now_utc()\n"
    assert _ambient_clock_violations(ast.parse(source), "probe.py") == []


@pytest.mark.parametrize(
    "source",
    [
        "import os\n",
        "from pathlib import Path\n",
        "import importlib\n",
        "import sys\n",
        "open('x')\n",
        "def f(path):\n    return path.open('rb')\n",
    ],
)
def test_the_filesystem_scan_detects_each_shape(source: str) -> None:
    assert _filesystem_violations(ast.parse(source), "probe.py") != []


def test_the_filesystem_scan_allows_pure_imports() -> None:
    source = (
        "from pydantic import Field\n"
        "from crypto_lab.domain.base import CanonicalModel\n"
    )
    assert _filesystem_violations(ast.parse(source), "probe.py") == []


@pytest.mark.parametrize(
    "source",
    [
        "from doubles.experiments import InMemoryBackingStore\n",
        "import tests.doubles.experiments\n",
        "from tests.doubles import experiments\n",
    ],
)
def test_the_test_double_scan_detects_each_shape(source: str) -> None:
    assert _test_double_violations(ast.parse(source), "probe.py") != []


def test_the_test_double_scan_ignores_docstring_text() -> None:
    source = '"""Implemented by the tests/doubles module, never imported here."""\n'
    assert _test_double_violations(ast.parse(source), "probe.py") == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from crypto_lab.datasets import models\n", "crypto_lab.datasets"),
        ("import crypto_lab.artifacts.ownership\n", "crypto_lab.artifacts.ownership"),
        ("from ..process_supervision import x\n", "crypto_lab.process_supervision"),
        ("from crypto_lab import audit\n", "crypto_lab.audit"),
        (
            "from crypto_lab.strategy.models import StrategySpec\n",
            "crypto_lab.strategy",
        ),
    ],
)
def test_the_out_of_scope_scan_detects_each_shape(source: str, expected: str) -> None:
    violations = _out_of_scope_violations(
        ast.parse(source), "probe.py", "crypto_lab.experiments"
    )
    assert violations != []
    assert any(expected in violation for violation in violations)


def test_the_out_of_scope_scan_allows_the_stage_five_edges() -> None:
    source = (
        "from crypto_lab.adapters.ports import CommandInvocationRepository\n"
        "from crypto_lab.domain.base import CanonicalModel\n"
        "from .ports import UnitOfWork\n"
    )
    assert (
        _out_of_scope_violations(
            ast.parse(source), "probe.py", "crypto_lab.experiments"
        )
        == []
    )


_PRIMITIVE_READER = """
class Reader:
    def get(self, diagnostic_id):
        return self._view.read(diagnostic_id)

    def get_many(self, diagnostic_ids):
        found = []
        for diagnostic_id in sorted(diagnostic_ids):
            found.append(self._view.read(diagnostic_id))
        return tuple(found)
"""
_TRAVERSING_READERS = (
    (
        "attribute walk",
        """
class Reader:
    def get(self, diagnostic_id):
        return self._view.read(diagnostic_id)

    def get_many(self, diagnostic_ids):
        found = []
        for diagnostic_id in diagnostic_ids:
            record = self._view.read(diagnostic_id)
            for child in record.causal_diagnostic_ids:
                found.append(self._view.read(child))
        return tuple(found)
""",
    ),
    (
        "while loop",
        """
class Reader:
    def get(self, diagnostic_id):
        return self._view.read(diagnostic_id)

    def get_many(self, diagnostic_ids):
        frontier = list(diagnostic_ids)
        while frontier:
            frontier.pop()
        return ()
""",
    ),
    (
        "self recursion",
        """
class Reader:
    def get(self, diagnostic_id):
        return self.get_many((diagnostic_id,))[0]

    def get_many(self, diagnostic_ids):
        return ()
""",
    ),
    (
        "delegated traversal",
        """
class Reader:
    def get(self, diagnostic_id):
        return self._view.read(diagnostic_id)

    def get_many(self, diagnostic_ids):
        return resolve_causal_closure(self, diagnostic_ids[0], now=None)
""",
    ),
    (
        "loop over a non-parameter",
        """
class Reader:
    def get(self, diagnostic_id):
        return self._view.read(diagnostic_id)

    def get_many(self, diagnostic_ids):
        for record in self._view.values():
            pass
        return ()
""",
    ),
)


def test_the_traversal_scan_allows_a_primitive_reader() -> None:
    (class_node,) = _reader_implementations(ast.parse(_PRIMITIVE_READER))
    assert _traversal_violations(class_node, "probe.py") == []


@pytest.mark.parametrize(
    ("label", "source"),
    _TRAVERSING_READERS,
    ids=[item[0] for item in _TRAVERSING_READERS],
)
def test_the_traversal_scan_detects_each_traversing_reader(
    label: str, source: str
) -> None:
    (class_node,) = _reader_implementations(ast.parse(source))
    assert _traversal_violations(class_node, "probe.py") != [], label


def test_the_reader_locator_skips_the_protocol_and_partial_classes() -> None:
    source = (
        "from typing import Protocol\n"
        "class Port(Protocol):\n"
        "    def get(self, x): ...\n"
        "    def get_many(self, x): ...\n"
        "class Half:\n"
        "    def get(self, x): ...\n"
    )
    assert _reader_implementations(ast.parse(source)) == ()


def test_the_ownership_scan_attributes_reads_and_calls_to_their_functions() -> None:
    source = (
        "def walk(reader, record):\n"
        "    reader.get_many(record.causal_diagnostic_ids)\n"
        "def build():\n"
        "    return make(causal_diagnostic_ids=())\n"
    )
    tree = ast.parse(source)
    assert _get_many_call_sites(tree) == ("walk",)
    assert _causal_closure_reads(tree) == ("walk",)
