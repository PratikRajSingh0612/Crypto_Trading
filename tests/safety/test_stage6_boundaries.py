"""Stage 6 source- and test-level safety guards (Stage 6 plan Task 9 step 2).

The plan names the facts this module pins: the fourteen Stage 6 source modules are
exactly the section 2.6 paths and none touches the filesystem, the environment, a
shell or an infrastructure root; exactly four reviewed classes carry a field
annotated with the raw ``AttemptToken`` grammar (plan section 13); no module under
``tests/`` or ``scripts/`` invokes a shell or a string command, and ``subprocess``
is imported by exactly the eleven allowlisted files (the ten of Stage 6 plus the
Stage 7 fake script, Stage 7 plan section 2.6); the fake adapter imports only its
seven standard-library roots; no ``crypto_lab`` module imports the test tree,
including its ``fake_adapters`` and ``contract`` packages; and the roadmap records
Stage 6 complete, with its Stage 7 deferred row retired by Stage 7 completion
(Stage 7 plan section 2.6, Task 9). Every scan is static and AST-based, and
every scan carries a planted-violation control, because a guard that cannot fail
is not a guard.

Declared readings, so nothing is inferred silently:

- "Stage 6 module" means exactly the fourteen paths plan section 2.6 tabulates,
  pinned here as a literal so a widened set cannot pass by omission. The Stage 5
  filesystem, environment, infrastructure and ambient-clock scans are reused
  over them.
- The no-shell scan (plan section 13) flags **calls** only: any call resolving to
  ``os.system``, ``os.popen``, ``os.startfile`` or ``os.spawn*`` anywhere under
  ``tests/`` and ``scripts/``; any ``subprocess`` call in a file outside the
  importer allowlist; and any ``subprocess`` call whose first positional argument
  is a string constant or whose keywords include ``shell=True``, allowlisted file
  or not. String constants and assignment targets are not calls and are not
  flagged: three merged test modules carry ``os.system`` only inside string
  constants, this module carries it inside its own controls, and a planted
  ``os.system = sentinel`` assignment proves the assignment-target exemption.
  Import aliases are resolved (``from os import system``, ``import subprocess as
  sp``) with the Stage 3 guard's resolver.
- The raw-token scan keys on the **annotation**, never on the field name: every
  class field whose annotation mentions the exact name ``AttemptToken`` is a
  carrier. The merged ``AttemptCreation.attempt_token``, typed by the
  ``AttemptTokenMaterial`` wrapper, is the near-miss control that proves the basis.
- The test-double scan is the Stage 5 root scan widened to the two Stage 6 test
  packages ``fake_adapters`` and ``contract``, so ``crypto_lab`` can import neither
  the fake executable nor the stand-in supervisor.
- The completion-status facts that plan section 2.6 does not tabulate live here:
  the Stage 6 completion row (its last clause now "Stage 7 complete"), the retired
  Stage 6 deferred row, the negative of the retired Stage 7 deferred row, the
  Stage 6 plan-approval line and the negative of its planned form. The three
  documentation surfaces themselves are pinned by the Stage 3 guard's Stage 7
  successor test.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest
from test_stage3_boundaries import (
    _ALLOWED_SOURCE_FILES,
    STAGE6_IMPLEMENTATION_COMMIT,
    STAGE6_PLAN,
    _environment_access_violations,
    _import_aliases,
    _imported_roots,
    _resolved_qualified_name,
)
from test_stage5_boundaries import (
    _ambient_clock_violations,
    _filesystem_violations,
    _infrastructure_violations,
    _parse,
    _source_files,
)

#: Plan section 2.6: the fourteen modules Stage 6 created, Task 1 through Task 7.
STAGE6_SOURCE_FILES: Final[tuple[str, ...]] = (
    "adapters/vocabulary.py",
    "adapters/limits.py",
    "adapters/paths.py",
    "adapters/catalog.py",
    "adapters/diagnostics.py",
    "adapters/envelopes.py",
    "adapters/commands.py",
    "adapters/negotiation.py",
    "adapters/events.py",
    "adapters/sanitization.py",
    "adapters/manifests.py",
    "adapters/exit_codes.py",
    "adapters/reconciliation.py",
    "experiments/semantic_outcome.py",
)
_ROADMAP: Final = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
_VERIFICATION_GUIDE: Final = "docs/development/verification.md"
_FAKE_ADAPTER: Final = "tests/fake_adapters/fake_adapter.py"
_HARNESS: Final = "tests/contract/harness.py"
_HARNESS_SAFETY: Final = "tests/contract/test_harness_safety.py"
_THIS_GUARD: Final = "tests/safety/test_stage6_boundaries.py"
#: Plan Task 9 step 2: the fake adapter's complete import surface.
_FAKE_ADAPTER_ROOTS: Final = frozenset(
    {"argparse", "datetime", "hashlib", "json", "os", "sys", "time"}
)
#: Plan Task 9 step 2: the nine importers at the planning base plus the harness; the
#: Stage 7 plan (section 2.6, Task 8) adds the Stage 7 fake script as the eleventh;
#: the Stage 8 plan (section 2.6, Task 6) adds the persistence interrupted-writer
#: test, which launches the one child interpreter of case C-17, as the twelfth.
_SUBPROCESS_IMPORTERS: Final = frozenset(
    {
        "tests/contract/harness.py",
        "tests/fake_adapters/supervision_fake.py",
        "tests/integration/persistence/test_wal_restart.py",
        "tests/safety/test_forbidden_runtime_paths.py",
        "tests/safety/test_gitnexus_development_tooling.py",
        "tests/safety/test_stage3_boundaries.py",
        "tests/safety/test_uv_launcher.py",
        "tests/unit/adapters/test_descriptors.py",
        "tests/unit/strategy/test_strategy_expressions.py",
        "tests/unit/test_cli.py",
        "tests/unit/test_package_layout.py",
        "tests/unit/test_schema_registry.py",
    }
)
#: Plan section 13: the three merged files that spell ``os.system`` only inside a
#: string or bytes constant; the negative controls of the calls-only reading.
_TEXT_ONLY_SHELL_FILES: Final = frozenset(
    {
        "tests/unit/strategy/test_strategy_loader.py",
        "tests/unit/strategy/test_strategy_yaml_source.py",
        "tests/unit/test_package_layout.py",
    }
)
_STAGE6_TEST_DOUBLE_ROOTS: Final = frozenset(
    {"contract", "doubles", "fake_adapters", "tests"}
)
_ATTEMPT_TOKEN_ANNOTATION: Final = "AttemptToken"  # noqa: S105 - a type name
#: Plan section 13: the exact classes permitted to carry a raw-token field, keyed
#: on the annotation, as (module, class, field).
_ATTEMPT_TOKEN_CARRIERS: Final = frozenset(
    {
        ("adapters/envelopes.py", "EngineRunRequest", "attempt_token"),
        ("adapters/events.py", "ProtocolEventEnvelope", "attempt_token"),
        ("adapters/manifests.py", "AdapterResultManifest", "attempt_token"),
        ("domain/engine_run.py", "AttemptTokenMaterial", "attempt_token"),
    }
)
_NEAR_MISS_CARRIER: Final = (
    "experiments/run_service.py",
    "AttemptCreation",
    "attempt_token",
)
_SHELL_CAPABLE_CALLS: Final = frozenset({"os.system", "os.popen", "os.startfile"})
_SHELL_CAPABLE_PREFIX: Final = "os.spawn"
_STAGE6_ROADMAP_ROW: Final = (
    "| 6 — Adapter Protocol and Fake-Adapter Contract Harness | Approved and "
    "executed | Implementation complete at "
    f"`{STAGE6_IMPLEMENTATION_COMMIT}` | Complete; explicit adapter catalog "
    "contracts, bootstrap descriptors and protocol negotiation, "
    "command-discriminated request envelopes, invocation-scoped stdout events with "
    "sequence, replay, and identity rules, validation results, untrusted adapter "
    "result manifests reconciled into core-sanitized manifests, stable exit "
    "mappings, incremental protocol validation, raw-token redaction, and executable "
    "fake adapters covering the 52-row contract matrix through a test-resident "
    "offline harness; the closed 35-schema registry — 8 new Stage 6 schemas with "
    "the 27 Stage 3, 4 and 5 schemas preserved byte-identical — together with the "
    "Stage 6 boundary guard, the end-to-end protocol flow, and this status were "
    "added by the separate Task 9 commit, which is not the implementation hash; "
    "verified offline on the complete verifier; GitNexus remains "
    "`DISABLED_WITH_EVIDENCE` with the manual source, reference, and diff fallback "
    # Stage 7 plan section 2.6: the one clause of this row Task 9 changes.
    "recorded; Stage 7 complete |"
)
_STAGE6_DEFERRED_ROW: Final = (
    "| 6 — Adapter Protocol and Fake-Adapter Contract Harness | Intentionally "
    "deferred until Stages 3 and 5 completion | Not started | Not evaluated |"
)
#: The roadmap's deferred Stage 7 row, which Stage 6 completion left exactly as it
#: was and which Stage 7 completion retired (Stage 7 plan section 2.6); its
#: completion successor is pinned by ``tests/safety/test_stage7_boundaries.py``.
_STAGE7_ROADMAP_ROW: Final = (
    "| 7 — Windows Process Supervision | Intentionally deferred until Stage 6 "
    "completion | Not started | Not evaluated |"
)


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def _tree_files(repository_root: Path, *roots: str) -> tuple[Path, ...]:
    files: list[Path] = []
    for root in roots:
        files.extend((repository_root / root).rglob("*.py"))
    return tuple(sorted(files))


def _label(repository_root: Path, path: Path) -> str:
    return path.relative_to(repository_root).as_posix()


def _shell_violations(
    tree: ast.AST, label: str, *, subprocess_importer: bool
) -> list[str]:
    """Plan section 13, calls only; see the module docstring for the reading."""
    aliases = _import_aliases(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _resolved_qualified_name(node.func, aliases)
        if target is None:
            continue
        if target in _SHELL_CAPABLE_CALLS or target.startswith(_SHELL_CAPABLE_PREFIX):
            violations.append(f"{label}:{node.lineno}: shell-capable call {target}")
            continue
        if target != "subprocess" and not target.startswith("subprocess."):
            continue
        if not subprocess_importer:
            violations.append(
                f"{label}:{node.lineno}: subprocess call outside the importer allowlist"
            )
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            violations.append(
                f"{label}:{node.lineno}: subprocess call with a string command"
            )
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                violations.append(
                    f"{label}:{node.lineno}: subprocess call with shell=True"
                )
    return violations


def _annotation_names(annotation: ast.AST) -> frozenset[str]:
    """Every simple name an annotation mentions, string forward references
    included (parsed as expressions where they parse)."""
    names: set[str] = set()
    for node in ast.walk(annotation):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                nested = ast.parse(node.value, mode="eval")
            except SyntaxError:
                continue
            names |= _annotation_names(nested)
    return frozenset(names)


def _attempt_token_fields(tree: ast.AST, label: str) -> list[tuple[str, str, str]]:
    """Every (module, class, field) whose annotation mentions ``AttemptToken``."""
    found: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.AnnAssign):
                continue
            if not isinstance(statement.target, ast.Name):
                continue
            if _ATTEMPT_TOKEN_ANNOTATION in _annotation_names(statement.annotation):
                found.append((label, node.name, statement.target.id))
    return found


def _stage6_test_double_violations(tree: ast.AST, label: str) -> list[str]:
    return [
        f"{label}: test-tree import {root}"
        for root in _imported_roots(tree)
        if root in _STAGE6_TEST_DOUBLE_ROOTS
    ]


# --------------------------------------------------------------------------
# Source-tree facts
# --------------------------------------------------------------------------


def test_the_stage_six_source_files_are_exactly_the_fourteen_plan_paths(
    repository_root: Path,
) -> None:
    assert len(STAGE6_SOURCE_FILES) == 14
    assert len(set(STAGE6_SOURCE_FILES)) == 14
    assert set(STAGE6_SOURCE_FILES) <= _ALLOWED_SOURCE_FILES
    for relative_path in STAGE6_SOURCE_FILES:
        assert (repository_root / "src/crypto_lab" / relative_path).is_file()


def test_stage_six_modules_touch_neither_filesystem_environment_clock_nor_shell(
    repository_root: Path,
) -> None:
    violations: list[str] = []
    for relative_path in STAGE6_SOURCE_FILES:
        tree = _parse(repository_root / "src/crypto_lab" / relative_path)
        violations.extend(_filesystem_violations(tree, relative_path))
        violations.extend(_environment_access_violations(tree, relative_path))
        violations.extend(_infrastructure_violations(tree, relative_path))
        violations.extend(_ambient_clock_violations(tree, relative_path))
        violations.extend(
            _shell_violations(tree, relative_path, subprocess_importer=False)
        )
    assert violations == []


def test_only_the_four_reviewed_classes_carry_a_raw_attempt_token_field(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    found: set[tuple[str, str, str]] = set()
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        found.update(_attempt_token_fields(_parse(path), label))
    assert found == _ATTEMPT_TOKEN_CARRIERS
    # The near miss: the merged `AttemptCreation` carries `attempt_token`, typed by
    # the `AttemptTokenMaterial` wrapper, and the scan (keyed on the annotation, not
    # the name) does not list it -- which proves the basis of the four.
    module, class_name, field_name = _NEAR_MISS_CARRIER
    tree = _parse(source / module)
    (class_node,) = (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    (statement,) = (
        item
        for item in class_node.body
        if isinstance(item, ast.AnnAssign)
        and isinstance(item.target, ast.Name)
        and item.target.id == field_name
    )
    assert "AttemptTokenMaterial" in _annotation_names(statement.annotation)
    assert _NEAR_MISS_CARRIER not in found


def test_no_source_module_imports_the_stage_six_test_tree(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    violations: list[str] = []
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        violations.extend(_stage6_test_double_violations(_parse(path), label))
    assert violations == []


# --------------------------------------------------------------------------
# Test-tree facts
# --------------------------------------------------------------------------


def test_the_fake_adapter_imports_only_its_seven_stdlib_roots(
    repository_root: Path,
) -> None:
    tree = _parse(repository_root / _FAKE_ADAPTER)
    roots = _imported_roots(tree)
    assert frozenset(roots) == _FAKE_ADAPTER_ROOTS
    assert "subprocess" not in roots
    assert "crypto_lab" not in roots
    assert _shell_violations(tree, _FAKE_ADAPTER, subprocess_importer=False) == []


def test_no_test_or_script_module_invokes_a_shell_or_a_string_command(
    repository_root: Path,
) -> None:
    importers: set[str] = set()
    violations: list[str] = []
    for path in _tree_files(repository_root, "tests", "scripts"):
        label = _label(repository_root, path)
        tree = _parse(path)
        if "subprocess" in _imported_roots(tree):
            importers.add(label)
        violations.extend(
            _shell_violations(
                tree, label, subprocess_importer=label in _SUBPROCESS_IMPORTERS
            )
        )
    assert violations == []
    assert importers == set(_SUBPROCESS_IMPORTERS)
    assert len(_SUBPROCESS_IMPORTERS) == 12
    assert _HARNESS in _SUBPROCESS_IMPORTERS
    # The harness safety test inspects the launch helper's returned arguments and
    # must not import subprocess; the allowlist enforces it.
    assert _HARNESS_SAFETY not in _SUBPROCESS_IMPORTERS
    assert (repository_root / _HARNESS_SAFETY).is_file()


def test_every_os_system_mention_in_the_test_tree_is_text_not_a_call(
    repository_root: Path,
) -> None:
    mentions: set[str] = set()
    for path in _tree_files(repository_root, "tests"):
        label = _label(repository_root, path)
        if "os.system" in path.read_text(encoding="utf-8"):
            mentions.add(label)
    assert mentions == _TEXT_ONLY_SHELL_FILES | {_THIS_GUARD}
    for label in _TEXT_ONLY_SHELL_FILES:
        tree = _parse(repository_root / label)
        assert (
            _shell_violations(
                tree, label, subprocess_importer=label in _SUBPROCESS_IMPORTERS
            )
            == []
        )


# --------------------------------------------------------------------------
# Completion-status facts plan section 2.6 does not tabulate
# --------------------------------------------------------------------------


def test_the_roadmap_records_stage_six_complete_and_stage_seven_not_started(
    repository_root: Path,
) -> None:
    """The test name is historical and is kept (Stage 7 plan section 2.6).

    Stage 7 completion retired the Stage 7 deferred row this test once pinned
    positively -- the positive became this negative, exactly as the Stage 6 guard's
    predecessor did for the Stage 5 guard -- and the Stage 6 completion row's last
    clause became "Stage 7 complete". The Stage 7 completion row, the Stage 8
    deferred row and the Stage 7 plan-approval line are pinned by the Task 9-owned
    ``tests/safety/test_stage7_boundaries.py``.
    """
    roadmap = (repository_root / _ROADMAP).read_text(encoding="utf-8")
    readme = (repository_root / "README.md").read_text(encoding="utf-8")
    guide = (repository_root / _VERIFICATION_GUIDE).read_text(encoding="utf-8")
    assert _STAGE6_ROADMAP_ROW in roadmap
    assert _STAGE6_DEFERRED_ROW not in roadmap
    assert _STAGE7_ROADMAP_ROW not in roadmap
    assert STAGE6_IMPLEMENTATION_COMMIT in roadmap
    assert f"**Approved detailed implementation plan:** `{STAGE6_PLAN}`." in roadmap
    assert f"**Planned detailed implementation plan:** `{STAGE6_PLAN}`." not in roadmap
    assert "Stage 6 not started" not in roadmap
    assert "Stage 6 has not started" not in readme
    assert "Stage 6 is not started" not in guide


# --------------------------------------------------------------------------
# Planted-violation controls
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system('dir')\n",
        "from os import system\nsystem('dir')\n",
        "import os as operating\noperating.system('dir')\n",
        "import os\nos.popen('dir')\n",
        "import os\nos.startfile('x')\n",
        "import os\nos.spawnl(0, 'x')\n",
        "import os\nos.spawnv(0, 'x', [])\n",
        "import subprocess\nsubprocess.run('dir')\n",
        "import subprocess\nsubprocess.run(['dir'], shell=True)\n",
        "import subprocess as sp\nsp.Popen(['dir'], shell=True)\n",
        "from subprocess import run\nrun('dir')\n",
        "from subprocess import check_output\ncheck_output('dir', shell=True)\n",
    ],
)
def test_the_shell_scan_detects_each_call_shape(source: str) -> None:
    assert _shell_violations(ast.parse(source), "probe.py", subprocess_importer=True)


def test_the_shell_scan_flags_subprocess_calls_outside_the_allowlist() -> None:
    source = "import subprocess\nsubprocess.run(['dir'], shell=False)\n"
    assert (
        _shell_violations(ast.parse(source), "probe.py", subprocess_importer=True) == []
    )
    assert _shell_violations(
        ast.parse(source), "probe.py", subprocess_importer=False
    ) == ["probe.py:2: subprocess call outside the importer allowlist"]


@pytest.mark.parametrize(
    "source",
    [
        # The assignment-target exemption (plan section 13): not a call.
        "import os\nos.system = sentinel\n",
        "import os\nsentinel = os.system\n",
        "value = 'os.system'\n",
        "value = b'import os; os.system(\"dir\")'\n",
        "import subprocess\nsubprocess.run(argv, shell=False)\n",
        "import subprocess\nsubprocess.Popen(argv, stdin=subprocess.DEVNULL)\n",
        "import subprocess\nflag = subprocess.PIPE\n",
    ],
)
def test_the_shell_scan_allows_text_assignment_and_list_argv(source: str) -> None:
    assert (
        _shell_violations(ast.parse(source), "probe.py", subprocess_importer=True) == []
    )


@pytest.mark.parametrize(
    "annotation",
    [
        "AttemptToken",
        "Annotated[AttemptToken, Field()]",
        "'AttemptToken'",
        "tuple[AttemptToken, ...]",
        "identifiers.AttemptToken",
        "AttemptToken | MISSING",
    ],
)
def test_the_attempt_token_scan_detects_each_annotation_shape(annotation: str) -> None:
    source = f"class X(CanonicalModel):\n    token: {annotation}\n"
    assert _attempt_token_fields(ast.parse(source), "probe.py") == [
        ("probe.py", "X", "token")
    ]


@pytest.mark.parametrize(
    "source",
    [
        # The name is not the basis: a field called attempt_token typed otherwise.
        "class Y(CanonicalModel):\n    attempt_token: AttemptTokenMaterial | MISSING\n",
        "class Y(CanonicalModel):\n    attempt_token: str\n",
        "class Y(CanonicalModel):\n    attempt_token_hash: Sha256\n",
        # A parameter annotation is not a class field.
        "def redact(token: AttemptToken) -> None:\n    pass\n",
        # Text mentioning the grammar is not an annotation.
        'class Y(CanonicalModel):\n    """Carries no AttemptToken."""\n    x: int\n',
    ],
)
def test_the_attempt_token_scan_ignores_names_parameters_and_text(
    source: str,
) -> None:
    assert _attempt_token_fields(ast.parse(source), "probe.py") == []


@pytest.mark.parametrize(
    "source",
    [
        "from contract.harness import build_harness\n",
        "import fake_adapters.fake_adapter\n",
        "from fake_adapters import fake_adapter\n",
        "from doubles.experiments import FixedClock\n",
        "from tests.contract import harness\n",
    ],
)
def test_the_widened_test_double_scan_detects_each_root(source: str) -> None:
    assert _stage6_test_double_violations(ast.parse(source), "probe.py") != []


def test_the_widened_test_double_scan_allows_package_imports() -> None:
    source = (
        "from crypto_lab.adapters import events\n"
        "from crypto_lab.domain.base import CanonicalModel\n"
    )
    assert _stage6_test_double_violations(ast.parse(source), "probe.py") == []


def test_the_fake_adapter_root_census_detects_a_planted_import() -> None:
    planted = "import argparse\nimport pathlib\n"
    assert frozenset(_imported_roots(ast.parse(planted))) != _FAKE_ADAPTER_ROOTS
    assert "pathlib" in _imported_roots(ast.parse(planted))
