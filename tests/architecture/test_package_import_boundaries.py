"""Enforce the ``strategy`` and ``capabilities`` inward-dependency boundaries.

Specification section 27.1 declares the dependency-direction table normative and
gives both packages exactly one allowed inward dependency: ``domain``. Plan
section 5.7 exists because specification section 8.2 places ``AdapterDescriptor``,
``RuntimeAvailabilityObservation``, and ``ComparisonLevel`` in the resolver
signature: rather than add the ``capabilities -> adapters`` edge that table
forbids, Stage 4 relocated those contracts into ``domain``. This test is what
makes the relocation binding instead of incidental.

The ``strategy`` assertion is **preventive**: it begins green, because Task 2
through Task 5 already respected the boundary. It is declared here rather than
asserted for the first time so a later stage cannot quietly add an edge.

A local scanner is used rather than the one in ``test_domain_import_boundary.py``:
that module is specialized to the domain root, is outside this task's file map,
and generalizing it would change a committed guard for a caller that does not need
it.

Stage 5 Task 9 adds ``experiments`` and ``adapters`` to the same scanner. The
``experiments`` prohibited set names the architecturally forbidden edges
(``persistence``, ``configuration``, ``cli`` and the composition module); its
allowlist is a **Stage 5 scope closure**, deliberately narrower than the section
27.1 table, which also permits ``strategy``, ``datasets``, ``artifacts``,
``process_supervision`` and ``audit``: those are out of Stage 5's scope and are
asserted absent by ``tests/safety/test_stage5_boundaries.py`` as well, so a later
stage that adds one of those edges must widen this allowlist explicitly. The
``adapters`` allowlist is the 27.1 shape: ``domain`` and itself.

Stage 7 Task 2 (Stage 7 plan section 2.6) adds ``process_supervision`` to the same
scanner. Its allowlist is the plan's **Stage 7 scope closure** -- ``domain``,
``adapters`` and itself -- deliberately narrower than the section 27.1 table, which
also permits ``audit`` abstractions: ``audit`` is Stage 9's package, so a planted
``audit`` edge must surface as unexpected. The prohibited set names every other
central package, ``experiments`` first, because the supervisor drives the
application layer through a structural port and never imports it (specification
section 8: ``process_supervision`` implements an application-facing port over
adapter protocol types).

Stage 8 Task 1 (Stage 8 plan section 2.6) adds ``persistence`` to the same scanner.
Its allowlist is the plan's **package-level closure** -- ``domain``, the port-bearing
packages ``experiments``, ``adapters`` and ``process_supervision``, the record packages
``artifacts``, ``datasets`` and ``strategy``, ``configuration`` and itself -- with a
positive anchor that grows per task (Task 1: ``domain`` and ``configuration``; Task 3:
``artifacts``, ``datasets`` and ``strategy``, the record packages the codecs and the
schema's generated CHECK lists consume); the
Stage 8 guard narrows the allowance to the exact module set in Task 8. The prohibited
set names ``capabilities``, ``cli`` and the composition module: the implementation of
the application-owned ports never imports the resolver, a composition root or the
registry that composes the layers, and ``audit`` stays outside the closure because it
is Stage 9's package.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from importlib.util import resolve_name
from pathlib import Path

import pytest

_CAPABILITIES = "capabilities"
_STRATEGY = "strategy"
_EXPERIMENTS = "experiments"
_ADAPTERS = "adapters"
#: Every central package other than ``domain`` and the scanned package itself.
#: Plan Task 6 step 11 names ``adapters`` first and then the other eight; ``cli``
#: is included because a composition root must never be imported by a layer.
_PROHIBITED_FOR_CAPABILITIES: tuple[str, ...] = (
    "crypto_lab.adapters",
    "crypto_lab.strategy",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.artifacts",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.audit",
    "crypto_lab.cli",
)
_PROHIBITED_FOR_STRATEGY: tuple[str, ...] = (
    "crypto_lab.adapters",
    "crypto_lab.capabilities",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.artifacts",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.audit",
    "crypto_lab.cli",
)
#: ``schema_registry`` sits outside the layered packages and may import inward, so
#: a layer importing *it* would invert the direction.
_COMPOSITION_MODULE = "crypto_lab.schema_registry"
#: Stage 5 plan Task 9: the edges section 27.1 forbids the application layer.
#: ``configuration`` is prohibited because ``experiments`` may not import it (plan
#: 2.2 and 2.3: requests carry the material hash by value instead); ``persistence``
#: because the application never imports a concrete implementation; ``cli`` because
#: a composition root is never imported by a layer; ``schema_registry`` is repeated
#: here so the scanner's self-test names it explicitly for this package too.
_PROHIBITED_FOR_EXPERIMENTS: tuple[str, ...] = (
    "crypto_lab.persistence",
    "crypto_lab.configuration",
    "crypto_lab.cli",
    _COMPOSITION_MODULE,
)
#: Stage 5 plan Task 9: the scope closure of ``experiments`` (module docstring).
_ALLOWED_FOR_EXPERIMENTS: tuple[str, ...] = (
    "crypto_lab.domain",
    "crypto_lab.adapters",
    "crypto_lab.capabilities",
    "crypto_lab.experiments",
)
#: Section 27.1: ``adapters`` may depend on canonical domain types alone.
_ALLOWED_FOR_ADAPTERS: tuple[str, ...] = ("crypto_lab.domain", "crypto_lab.adapters")
_PROCESS_SUPERVISION = "process_supervision"
#: Stage 7 plan section 2.6: every central package ``process_supervision`` may never
#: reach. ``experiments`` is first (the port direction of specification section 8);
#: ``audit`` is listed although section 27.1 would permit its abstractions, because
#: it is Stage 9's package and outside the Stage 7 closure; ``schema_registry`` is
#: repeated here so the scanner's self-test names it explicitly for this package too.
_PROHIBITED_FOR_PROCESS_SUPERVISION: tuple[str, ...] = (
    "crypto_lab.experiments",
    "crypto_lab.strategy",
    "crypto_lab.capabilities",
    "crypto_lab.datasets",
    "crypto_lab.artifacts",
    "crypto_lab.persistence",
    "crypto_lab.configuration",
    "crypto_lab.audit",
    "crypto_lab.cli",
    _COMPOSITION_MODULE,
)
#: Stage 7 plan section 2.6: the scope closure of ``process_supervision``.
_ALLOWED_FOR_PROCESS_SUPERVISION: tuple[str, ...] = (
    "crypto_lab.domain",
    "crypto_lab.adapters",
    "crypto_lab.process_supervision",
)
_PERSISTENCE = "persistence"
#: Stage 8 plan section 2.6: the central packages ``persistence`` may never reach --
#: the resolver, a composition root and the composition module (repeated here so the
#: scanner's self-test names it explicitly for this package too).
_PROHIBITED_FOR_PERSISTENCE: tuple[str, ...] = (
    "crypto_lab.capabilities",
    "crypto_lab.cli",
    "crypto_lab.schema_registry",
)
#: Stage 8 plan section 2.6: the package-level closure of ``persistence`` (module
#: docstring); the Stage 8 guard narrows it to the exact module set in Task 8.
_ALLOWED_FOR_PERSISTENCE: tuple[str, ...] = (
    "crypto_lab.domain",
    "crypto_lab.experiments",
    "crypto_lab.adapters",
    "crypto_lab.process_supervision",
    "crypto_lab.artifacts",
    "crypto_lab.datasets",
    "crypto_lab.strategy",
    "crypto_lab.configuration",
    "crypto_lab.persistence",
)


@dataclass(frozen=True, order=True, slots=True)
class PackageImportViolation:
    """One import that crosses a package boundary the table forbids."""

    relative_path: str
    line_number: int
    imported_name: str


def _module_package(source_path: Path, package_root: Path, package: str) -> str:
    parts = list(source_path.relative_to(package_root).with_suffix("").parts)
    parts.pop()
    return ".".join(("crypto_lab", package, *parts))


def _imported_names(
    node: ast.Import | ast.ImportFrom,
    module_package: str,
) -> tuple[str, ...]:
    """Resolve one import node to the absolute names it actually reaches.

    ``from crypto_lab import adapters`` names the subpackage in ``node.names``
    rather than in ``node.module``, and a relative import names nothing absolute at
    all, so both shapes are expanded here. Without that, the two easiest ways to
    write a forbidden import would both pass.
    """
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    base = node.module or ""
    if node.level > 0:
        base = resolve_name("." * node.level + base, module_package)
    if base == "crypto_lab":
        return tuple(f"crypto_lab.{alias.name}" for alias in node.names)
    return (base,)


def _is_within(imported_name: str, package_name: str) -> bool:
    return imported_name == package_name or imported_name.startswith(f"{package_name}.")


def find_package_import_violations(
    package_root: Path,
    package: str,
    prohibited: tuple[str, ...],
) -> tuple[PackageImportViolation, ...]:
    """Return every prohibited import below one central package root.

    Every ``Import`` and ``ImportFrom`` node is walked, including function-local
    ones, so deferring an import inside a function body does not evade the check.
    """
    violations: list[PackageImportViolation] = []
    for source_path in sorted(
        package_root.rglob("*.py"), key=lambda path: path.as_posix()
    ):
        tree = ast.parse(
            source_path.read_text(encoding="utf-8"), filename=str(source_path)
        )
        module_package = _module_package(source_path, package_root, package)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Import | ast.ImportFrom):
                continue
            for imported_name in _imported_names(node, module_package):
                forbidden = any(
                    _is_within(imported_name, candidate) for candidate in prohibited
                ) or _is_within(imported_name, _COMPOSITION_MODULE)
                if forbidden:
                    violations.append(
                        PackageImportViolation(
                            relative_path=source_path.relative_to(
                                package_root
                            ).as_posix(),
                            line_number=node.lineno,
                            imported_name=imported_name,
                        )
                    )
    return tuple(sorted(violations))


def _allowed_project_imports(
    package_root: Path,
    package: str,
) -> tuple[str, ...]:
    """Return every ``crypto_lab`` import reached from one package, deduplicated."""
    reached: set[str] = set()
    for source_path in sorted(
        package_root.rglob("*.py"), key=lambda path: path.as_posix()
    ):
        tree = ast.parse(
            source_path.read_text(encoding="utf-8"), filename=str(source_path)
        )
        module_package = _module_package(source_path, package_root, package)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Import | ast.ImportFrom):
                continue
            for imported_name in _imported_names(node, module_package):
                if imported_name.startswith("crypto_lab"):
                    reached.add(imported_name)
    return tuple(sorted(reached))


def _package_root(repository_root: Path, package: str) -> Path:
    return repository_root / "src" / "crypto_lab" / package


# --------------------------------------------------------------------------
# The repository assertions
# --------------------------------------------------------------------------


def test_capabilities_imports_nothing_from_any_prohibited_package(
    repository_root: Path,
) -> None:
    assert (
        find_package_import_violations(
            _package_root(repository_root, _CAPABILITIES),
            _CAPABILITIES,
            _PROHIBITED_FOR_CAPABILITIES,
        )
        == ()
    )


def test_capabilities_reaches_only_domain_and_itself(
    repository_root: Path,
) -> None:
    """An allowlist, not only a denylist.

    A denylist over today's package names would pass silently the moment a new
    central package appears. This asserts the positive shape of section 27.1's
    single allowed inward dependency instead.
    """
    reached = _allowed_project_imports(
        _package_root(repository_root, _CAPABILITIES), _CAPABILITIES
    )
    unexpected = tuple(
        name
        for name in reached
        if not (
            _is_within(name, "crypto_lab.domain")
            or _is_within(name, "crypto_lab.capabilities")
        )
    )
    assert unexpected == ()
    # The relocation is the point: the resolver's descriptor and availability
    # contracts must be reached through `domain`, never through `adapters`.
    assert "crypto_lab.domain.descriptors" in reached


def test_strategy_imports_nothing_from_any_prohibited_package(
    repository_root: Path,
) -> None:
    """Preventive: this begins green and exists so it cannot silently stop being."""
    assert (
        find_package_import_violations(
            _package_root(repository_root, _STRATEGY),
            _STRATEGY,
            _PROHIBITED_FOR_STRATEGY,
        )
        == ()
    )


def test_strategy_reaches_only_domain_and_itself(repository_root: Path) -> None:
    """Preventive, for the same reason as above."""
    reached = _allowed_project_imports(
        _package_root(repository_root, _STRATEGY), _STRATEGY
    )
    unexpected = tuple(
        name
        for name in reached
        if not (
            _is_within(name, "crypto_lab.domain")
            or _is_within(name, "crypto_lab.strategy")
        )
    )
    assert unexpected == ()


def test_experiments_imports_nothing_from_any_prohibited_package(
    repository_root: Path,
) -> None:
    """Stage 5 plan Task 9: the application layer never imports ``persistence``,
    ``configuration``, ``cli`` or the composition module."""
    assert (
        find_package_import_violations(
            _package_root(repository_root, _EXPERIMENTS),
            _EXPERIMENTS,
            _PROHIBITED_FOR_EXPERIMENTS,
        )
        == ()
    )


def test_experiments_reaches_only_its_stage_five_allowlist(
    repository_root: Path,
) -> None:
    """The Stage 5 scope closure of the application layer (module docstring).

    Anchored positively on the one cross-package edge Stage 5 actually takes, the
    ``CommandInvocationRepository`` port that plan section 2.4 places in
    ``adapters``, so the assertion cannot pass on an empty scan.
    """
    reached = _allowed_project_imports(
        _package_root(repository_root, _EXPERIMENTS), _EXPERIMENTS
    )
    unexpected = tuple(
        name
        for name in reached
        if not any(_is_within(name, allowed) for allowed in _ALLOWED_FOR_EXPERIMENTS)
    )
    assert unexpected == ()
    assert "crypto_lab.adapters.ports" in reached
    assert "crypto_lab.domain.base" in reached


def test_adapters_reaches_only_domain_and_itself(repository_root: Path) -> None:
    """Section 27.1: ``adapters`` depends on canonical domain types alone; the
    Stage 5 port added to it (plan 2.4) keeps that shape."""
    reached = _allowed_project_imports(
        _package_root(repository_root, _ADAPTERS), _ADAPTERS
    )
    unexpected = tuple(
        name
        for name in reached
        if not any(_is_within(name, allowed) for allowed in _ALLOWED_FOR_ADAPTERS)
    )
    assert unexpected == ()
    assert "crypto_lab.domain.command_invocation" in reached


def test_process_supervision_imports_nothing_from_any_prohibited_package(
    repository_root: Path,
) -> None:
    """Stage 7 plan section 2.6: the supervisor never imports ``experiments`` (it
    drives the application layer through a structural port), nor any other central
    package outside ``domain`` and ``adapters``."""
    assert (
        find_package_import_violations(
            _package_root(repository_root, _PROCESS_SUPERVISION),
            _PROCESS_SUPERVISION,
            _PROHIBITED_FOR_PROCESS_SUPERVISION,
        )
        == ()
    )


def test_process_supervision_reaches_only_domain_adapters_and_itself(
    repository_root: Path,
) -> None:
    """The Stage 7 scope closure of ``process_supervision`` (module docstring).

    Anchored positively on the two cross-package edges Task 2 actually takes -- the
    ``AdapterCommand``/``CommandResult`` contracts of ``adapters.commands`` and the
    ``ProcessIdentity``/``CommandInvocationRecord`` records of
    ``domain.command_invocation`` -- so the assertion cannot pass on an empty scan.
    """
    reached = _allowed_project_imports(
        _package_root(repository_root, _PROCESS_SUPERVISION), _PROCESS_SUPERVISION
    )
    unexpected = tuple(
        name
        for name in reached
        if not any(
            _is_within(name, allowed) for allowed in _ALLOWED_FOR_PROCESS_SUPERVISION
        )
    )
    assert unexpected == ()
    assert "crypto_lab.adapters.commands" in reached
    assert "crypto_lab.domain.command_invocation" in reached


def test_persistence_imports_nothing_from_any_prohibited_package(
    repository_root: Path,
) -> None:
    """Stage 8 plan section 2.6: the implementation of the application-owned ports
    never imports ``capabilities``, ``cli`` or the composition module."""
    # The tuple spells the composition module as a literal so the Task 1 guard
    # test can ``literal_eval`` it; this pin keeps the two spellings from drifting.
    assert _PROHIBITED_FOR_PERSISTENCE[-1] == _COMPOSITION_MODULE
    assert (
        find_package_import_violations(
            _package_root(repository_root, _PERSISTENCE),
            _PERSISTENCE,
            _PROHIBITED_FOR_PERSISTENCE,
        )
        == ()
    )


def test_persistence_reaches_only_its_stage_eight_allowlist(
    repository_root: Path,
) -> None:
    """The Stage 8 package-level closure of ``persistence`` (module docstring).

    Anchored positively on the cross-package edges the task actually takes, so the
    assertion cannot pass on an empty scan: Task 1 reaches ``domain`` (the ``Result``
    values and the ``Clock`` port) and ``configuration`` (``DatabaseConfig``); Task 3
    reaches ``artifacts`` (the owner variants and ``ARTIFACT_OWNER_ADAPTER``),
    ``datasets`` (the descriptor, partition and identity helper) and ``strategy``
    (``StrategyVersion`` and its profile version); Task 4 reaches ``experiments``
    (the ``UnitOfWork`` member protocols and ``RetryDecisionInsertOutcome``) and
    ``adapters`` (the ``CommandInvocationRepository`` port and ``RunEvent``); Task 5
    reaches ``process_supervision`` (``RunReconciliationFacts``, the value the
    reconciliation source assembles) -- the direction is persistence to
    ``process_supervision``, never the reverse.
    """
    reached = _allowed_project_imports(
        _package_root(repository_root, _PERSISTENCE), _PERSISTENCE
    )
    unexpected = tuple(
        name
        for name in reached
        if not any(_is_within(name, allowed) for allowed in _ALLOWED_FOR_PERSISTENCE)
    )
    assert unexpected == ()
    assert "crypto_lab.domain.results" in reached
    assert "crypto_lab.configuration.models" in reached
    assert "crypto_lab.artifacts.ownership" in reached
    assert "crypto_lab.datasets" in reached
    assert "crypto_lab.strategy.versioning" in reached
    assert "crypto_lab.experiments.ports" in reached
    assert "crypto_lab.adapters.ports" in reached
    assert "crypto_lab.process_supervision.models" in reached


# --------------------------------------------------------------------------
# Scanner self-tests -- a guard that cannot fail is not a guard
# --------------------------------------------------------------------------


def _write_package(tmp_path: Path, package: str, source: str) -> Path:
    package_root = tmp_path / "src" / "crypto_lab" / package
    package_root.mkdir(parents=True)
    (package_root / "sample.py").write_text(source, encoding="utf-8")
    return package_root


@pytest.mark.parametrize("prohibited_package", _PROHIBITED_FOR_CAPABILITIES)
def test_the_scanner_rejects_every_prohibited_package(
    tmp_path: Path,
    prohibited_package: str,
) -> None:
    package_root = _write_package(
        tmp_path, _CAPABILITIES, f"import {prohibited_package}\n"
    )

    violations = find_package_import_violations(
        package_root, _CAPABILITIES, _PROHIBITED_FOR_CAPABILITIES
    )

    assert tuple(item.imported_name for item in violations) == (prohibited_package,)


@pytest.mark.parametrize("prohibited_package", _PROHIBITED_FOR_EXPERIMENTS)
def test_the_scanner_rejects_every_package_prohibited_for_experiments(
    tmp_path: Path,
    prohibited_package: str,
) -> None:
    """Stage 5 Task 9: the same self-test over the ``experiments`` prohibited set."""
    package_root = _write_package(
        tmp_path, _EXPERIMENTS, f"import {prohibited_package}\n"
    )

    violations = find_package_import_violations(
        package_root, _EXPERIMENTS, _PROHIBITED_FOR_EXPERIMENTS
    )

    assert tuple(item.imported_name for item in violations) == (prohibited_package,)


def test_the_experiments_allowlist_rejects_a_table_permitted_out_of_scope_edge(
    tmp_path: Path,
) -> None:
    """The allowlist is a scope closure: ``strategy`` is permitted by section 27.1
    and still outside it, so a planted edge must surface as unexpected."""
    package_root = _write_package(
        tmp_path, _EXPERIMENTS, "from crypto_lab.strategy import models\n"
    )

    reached = _allowed_project_imports(package_root, _EXPERIMENTS)

    assert reached == ("crypto_lab.strategy",)
    assert not any(
        _is_within(reached[0], allowed) for allowed in _ALLOWED_FOR_EXPERIMENTS
    )


@pytest.mark.parametrize("prohibited_package", _PROHIBITED_FOR_PROCESS_SUPERVISION)
def test_the_scanner_rejects_every_package_prohibited_for_process_supervision(
    tmp_path: Path,
    prohibited_package: str,
) -> None:
    """Stage 7 Task 2: the same self-test over the ``process_supervision`` set."""
    package_root = _write_package(
        tmp_path, _PROCESS_SUPERVISION, f"import {prohibited_package}\n"
    )

    violations = find_package_import_violations(
        package_root, _PROCESS_SUPERVISION, _PROHIBITED_FOR_PROCESS_SUPERVISION
    )

    assert tuple(item.imported_name for item in violations) == (prohibited_package,)


def test_the_process_supervision_allowlist_rejects_the_table_permitted_audit_edge(
    tmp_path: Path,
) -> None:
    """The allowlist is a scope closure: ``audit`` abstractions are permitted by
    section 27.1 and still outside Stage 7, so a planted edge must surface as
    unexpected -- and a function-local one just the same."""
    package_root = _write_package(
        tmp_path,
        _PROCESS_SUPERVISION,
        "def observe() -> None:\n    from crypto_lab.audit import sink\n    del sink\n",
    )

    reached = _allowed_project_imports(package_root, _PROCESS_SUPERVISION)

    assert reached == ("crypto_lab.audit",)
    assert not any(
        _is_within(reached[0], allowed) for allowed in _ALLOWED_FOR_PROCESS_SUPERVISION
    )


@pytest.mark.parametrize("prohibited_package", _PROHIBITED_FOR_PERSISTENCE)
def test_the_scanner_rejects_every_package_prohibited_for_persistence(
    tmp_path: Path,
    prohibited_package: str,
) -> None:
    """Stage 8 Task 1: the same self-test over the ``persistence`` prohibited set."""
    package_root = _write_package(
        tmp_path, _PERSISTENCE, f"import {prohibited_package}\n"
    )

    violations = find_package_import_violations(
        package_root, _PERSISTENCE, _PROHIBITED_FOR_PERSISTENCE
    )

    assert tuple(item.imported_name for item in violations) == (prohibited_package,)


def test_the_persistence_allowlist_rejects_the_table_permitted_audit_edge(
    tmp_path: Path,
) -> None:
    """The allowlist is a scope closure: ``audit`` abstractions are permitted by
    section 27.1 and still outside Stage 8, so a planted edge must surface as
    unexpected."""
    package_root = _write_package(
        tmp_path, _PERSISTENCE, "from crypto_lab.audit import sink\n"
    )

    reached = _allowed_project_imports(package_root, _PERSISTENCE)

    assert reached == ("crypto_lab.audit",)
    assert not any(
        _is_within(reached[0], allowed) for allowed in _ALLOWED_FOR_PERSISTENCE
    )


@pytest.mark.parametrize(
    ("statement", "expected_name"),
    [
        ("import crypto_lab.adapters", "crypto_lab.adapters"),
        (
            "import crypto_lab.adapters.descriptors",
            "crypto_lab.adapters.descriptors",
        ),
        ("import crypto_lab.adapters as protocol", "crypto_lab.adapters"),
        ("from crypto_lab import adapters", "crypto_lab.adapters"),
        ("from crypto_lab import adapters as protocol", "crypto_lab.adapters"),
        (
            "from crypto_lab.adapters.descriptors import AdapterDescriptor",
            "crypto_lab.adapters.descriptors",
        ),
        (
            "from crypto_lab.schema_registry import SCHEMA_DEFINITIONS",
            _COMPOSITION_MODULE,
        ),
    ],
)
def test_the_scanner_rejects_each_import_shape(
    tmp_path: Path,
    statement: str,
    expected_name: str,
) -> None:
    package_root = _write_package(tmp_path, _CAPABILITIES, f"{statement}\n")

    violations = find_package_import_violations(
        package_root, _CAPABILITIES, _PROHIBITED_FOR_CAPABILITIES
    )

    assert tuple(item.imported_name for item in violations) == (expected_name,)


def test_the_scanner_reaches_a_function_local_import(tmp_path: Path) -> None:
    """A deferred import is the obvious way to dodge a module-level scan."""
    package_root = _write_package(
        tmp_path,
        _CAPABILITIES,
        "def resolve() -> None:\n"
        "    from crypto_lab.adapters.descriptors import AdapterDescriptor\n"
        "    del AdapterDescriptor\n",
    )

    violations = find_package_import_violations(
        package_root, _CAPABILITIES, _PROHIBITED_FOR_CAPABILITIES
    )

    assert tuple(item.imported_name for item in violations) == (
        "crypto_lab.adapters.descriptors",
    )
    assert violations[0].line_number == 2


def test_the_scanner_reaches_a_relative_import_that_escapes_the_package(
    tmp_path: Path,
) -> None:
    package_root = _write_package(
        tmp_path, _CAPABILITIES, "from ..adapters import descriptors\n"
    )

    violations = find_package_import_violations(
        package_root, _CAPABILITIES, _PROHIBITED_FOR_CAPABILITIES
    )

    assert tuple(item.imported_name for item in violations) == ("crypto_lab.adapters",)


def test_the_scanner_recurses_into_a_nested_module(tmp_path: Path) -> None:
    package_root = tmp_path / "src" / "crypto_lab" / _CAPABILITIES
    nested = package_root / "nested"
    nested.mkdir(parents=True)
    (nested / "sample.py").write_text(
        "import crypto_lab.experiments\n", encoding="utf-8"
    )

    violations = find_package_import_violations(
        package_root, _CAPABILITIES, _PROHIBITED_FOR_CAPABILITIES
    )

    assert violations == (
        PackageImportViolation(
            relative_path="nested/sample.py",
            line_number=1,
            imported_name="crypto_lab.experiments",
        ),
    )


def test_the_scanner_ignores_allowed_imports_and_lookalike_text(
    tmp_path: Path,
) -> None:
    package_root = _write_package(
        tmp_path,
        _CAPABILITIES,
        '''"""import crypto_lab.adapters inside a docstring."""
# from crypto_lab import adapters
from __future__ import annotations

from enum import StrEnum

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.descriptors import AdapterDescriptor

from . import sibling
from .nested import helper
''',
    )

    assert (
        find_package_import_violations(
            package_root, _CAPABILITIES, _PROHIBITED_FOR_CAPABILITIES
        )
        == ()
    )


def test_the_allowlist_scanner_reports_every_project_import(tmp_path: Path) -> None:
    package_root = _write_package(
        tmp_path,
        _CAPABILITIES,
        "from crypto_lab.domain.base import CanonicalModel\n"
        "from crypto_lab.experiments import service\n"
        "import json\n",
    )

    assert _allowed_project_imports(package_root, _CAPABILITIES) == (
        "crypto_lab.domain.base",
        "crypto_lab.experiments",
    )
