"""Stage 7 source-, test- and status-level safety guards (Stage 7 plan Task 9 step 1).

The plan names the facts this module pins: the twelve Stage 7 source modules are
exactly the section 2.6 paths; each of the five Stage 7 import roots (``threading``,
``queue``, ``ctypes``, ``subprocess``, ``asyncio``) is imported by exactly the modules
section 2.6 names and by no other source module; no Stage 7 module touches the
environment, an infrastructure root, an ambient clock or a shell, and the filesystem
only where the plan places it; the one ``subprocess.Popen`` call in ``src`` has exactly
the reviewed launch shape; ``process_supervision`` never imports ``experiments``,
``configuration``, ``persistence``, ``cli`` or the test tree and ``experiments`` never
imports ``process_supervision``; the Stage 7 fake script has exactly its eight import
roots, one ``sys.path.insert``, one ``KNOWN_ADAPTER_NAMES`` rebinding and one list-argv
``Popen``; the word "sandbox" occurs in ``process_supervision`` only inside the package
docstring's negative sentence; no Stage 7 module docstring carries a purity-scan
substring; and the roadmap records Stage 7 complete with Stage 8 not started. Every
scan is static and AST-based, and every scan carries a planted-violation control,
because a guard that cannot fail is not a guard.

Declared readings, so nothing is inferred silently:

- "Stage 7 module" means exactly the twelve paths plan section 2.6 tabulates, pinned as
  a literal so a widened set cannot pass by omission; the package ``__init__`` joins the
  text scans (it is where the negative sandbox sentence lives) but is a merged module.
- The plan's Task 9 step 1 splits the filesystem scan into "the pure modules" and a
  narrower scan over ``roots.py``, ``windows_api.py`` and ``windows_process.py``. The
  committed imports draw the line elsewhere: ``windows_api.py`` and
  ``windows_process.py`` import no filesystem root and take the full Stage 5 scan,
  while ``supervisor.py`` and ``reconciliation.py`` import ``pathlib`` (a merged root:
  pure ``PureWindowsPath`` arithmetic and the manifest-presence probe) and cannot. The
  guard therefore applies the strongest scan each module admits: the narrower scan
  (no ``os``, ``sys``, ``shutil``, ``tempfile``, ``stat``, ``io`` or ``glob`` root and
  no ``.cwd()``, ``.home()`` or ``.expanduser()`` call on any receiver) over all
  thirteen modules, the full scan over the ten that import no filesystem root, and for
  the three ``pathlib`` importers the full scan's residue pinned exactly -- the single
  ``pathlib`` root for ``supervisor.py`` and ``reconciliation.py`` with no ``open()``
  call, and the ``pathlib`` root plus the three ``open`` calls of ``roots.py``, the one
  module the plan places on the write boundary -- so any new root or call still fails.
- "List argv" for the ``Popen`` pins means a first positional argument that is an
  ``ast.List`` or a call to the builtin ``list``; a string constant, a name or anything
  else is a violation. Names are resolved through the Stage 3 guard's alias resolver.
- The root-confinement scan counts an import wherever it occurs; ``supervisor.py``
  imports ``asyncio`` function-locally inside ``invoke`` (plan 2.6) and is counted.
- The descendant creation-time rule is documented from the committed runtime, not from
  the plan: ``windows_api.py`` keeps a Toolhelp candidate only when its creation time is
  **not earlier than** its parent's recorded creation time (equality admitted, because
  two creations can share a clock tick). The verification guide states the same rule and
  both texts are pinned; the plan's own "later than" phrasing (plan 2026) is planning
  prose outside Task 9's file map and is recorded in the stage ledger.
- The Stage 8 negative boundary is proved as absence: the ``persistence`` package holds
  only its docstring-bearing ``__init__``, no tracked path under ``src``, ``tests``,
  ``scripts`` or ``schemas`` or at the repository root is Stage 8-shaped, every
  finalization and manifest name stays deferred, and the roadmap's Stage 8 row is the
  deferred row.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final

import pytest
from test_stage3_boundaries import (
    _ALLOWED_SOURCE_FILES,
    _DEFERRED_DEFINITIONS,
    STAGE7_IMPLEMENTATION_COMMIT,
    STAGE7_PLAN,
    _environment_access_violations,
    _import_aliases,
    _imported_roots,
    _resolved_qualified_name,
    _source_files,
)
from test_stage5_boundaries import (
    STAGE5_SOURCE_FILES,
    _ambient_clock_violations,
    _filesystem_violations,
    _imported_names,
    _infrastructure_violations,
    _module_package,
    _parse,
)
from test_stage6_boundaries import (
    _SUBPROCESS_IMPORTERS,
    STAGE6_SOURCE_FILES,
    _shell_violations,
    _stage6_test_double_violations,
)

#: Plan section 2.6: the twelve modules Stage 7 created, Task 1 through Task 7.
STAGE7_SOURCE_FILES: Final[tuple[str, ...]] = (
    "process_supervision/cancellation.py",
    "process_supervision/deadlines.py",
    "process_supervision/ports.py",
    "process_supervision/models.py",
    "process_supervision/diagnostics.py",
    "process_supervision/roots.py",
    "process_supervision/readers.py",
    "process_supervision/windows_api.py",
    "process_supervision/windows_process.py",
    "experiments/supervision_lifecycle.py",
    "process_supervision/supervisor.py",
    "process_supervision/reconciliation.py",
)
#: The merged package module that carries the negative sandbox sentence.
_PACKAGE_INIT: Final = "process_supervision/__init__.py"
#: The modules the Stage 5 filesystem scan runs over unchanged (declared reading 2).
_FULL_SCAN_MODULES: Final = frozenset(
    {
        "process_supervision/cancellation.py",
        "process_supervision/deadlines.py",
        "process_supervision/ports.py",
        "process_supervision/models.py",
        "process_supervision/diagnostics.py",
        "process_supervision/readers.py",
        "process_supervision/windows_api.py",
        "process_supervision/windows_process.py",
        "experiments/supervision_lifecycle.py",
        _PACKAGE_INIT,
    }
)
#: The modules that import ``pathlib``; each takes the narrower scan and has its
#: full-scan residue pinned exactly.
_PATHLIB_MODULES: Final = frozenset(
    {
        "process_supervision/roots.py",
        "process_supervision/supervisor.py",
        "process_supervision/reconciliation.py",
    }
)
_WRITE_BOUNDARY_MODULE: Final = "process_supervision/roots.py"
_WRITE_BOUNDARY_OPEN_CALLS: Final = 3
_NARROW_FILESYSTEM_ROOTS: Final = frozenset(
    {"os", "sys", "shutil", "tempfile", "stat", "io", "glob"}
)
_FORBIDDEN_PATH_CALLS: Final = frozenset(
    {"pathlib.Path.cwd", "pathlib.Path.home", "pathlib.Path.expanduser"}
)
#: The same three methods called on any object (``Path("x").expanduser()``), which the
#: alias resolver cannot name because the receiver is a call, not a name.
_FORBIDDEN_PATH_METHODS: Final = frozenset({"cwd", "home", "expanduser"})
#: Plan section 2.6: each Stage 7 root and the exact modules that may import it.
_ROOT_CONFINEMENT: Final[Mapping[str, frozenset[str]]] = {
    "threading": frozenset(
        {
            "process_supervision/cancellation.py",
            "process_supervision/readers.py",
            "process_supervision/supervisor.py",
        }
    ),
    "queue": frozenset({"process_supervision/readers.py"}),
    "ctypes": frozenset({"process_supervision/windows_api.py"}),
    "subprocess": frozenset({"process_supervision/windows_process.py"}),
    "asyncio": frozenset({"process_supervision/supervisor.py"}),
}
#: The one ``Popen`` importer and the reviewed shape of its one call (plan 2.6, 11).
_POPEN_MODULE: Final = "process_supervision/windows_process.py"
_POPEN_NOQA: Final = "# noqa: S603 - reviewed fixed catalog executable boundary"
_POPEN_KEYWORDS: Final = frozenset(
    {
        "shell",
        "env",
        "cwd",
        "stdin",
        "stdout",
        "stderr",
        "bufsize",
        "close_fds",
        "creationflags",
    }
)
_CREATE_SUSPENDED_MODULE: Final = "process_supervision/models.py"
_CREATE_SUSPENDED_NAME: Final = "CREATE_SUSPENDED"
_CREATE_SUSPENDED_VALUE: Final = 4
_PROCESS_SUPERVISION_PACKAGE: Final = "crypto_lab.process_supervision"
_EXPERIMENTS_PACKAGE: Final = "crypto_lab.experiments"
_PROHIBITED_FOR_PROCESS_SUPERVISION: Final[tuple[str, ...]] = (
    "crypto_lab.experiments",
    "crypto_lab.configuration",
    "crypto_lab.persistence",
    "crypto_lab.cli",
)
_PROHIBITED_FOR_EXPERIMENTS: Final[tuple[str, ...]] = (
    "crypto_lab.process_supervision",
)
_SANDBOX: Final = "sandbox"
_SANDBOX_NEGATIVE_SENTENCE: Final = "is not a security sandbox"
#: The substrings the mirrored purity scan and the merged port-contract scan deny.
_DOCSTRING_DENYLIST: Final[tuple[str, ...]] = (
    "time.time",
    "random.",
    "datetime.now",
    "uuid4(",
    "os.environ",
    "import random",
    "import doubles",
    "from doubles",
)
#: Plan section 9.1: the Stage 7 fake script and its exact import surface.
_SUPERVISION_FAKE: Final = "tests/fake_adapters/supervision_fake.py"
_SUPERVISION_FAKE_ROOTS: Final = frozenset(
    {"argparse", "fake_adapter", "json", "os", "signal", "subprocess", "sys", "time"}
)
_FAKE_POPEN_NOQA: Final = "# noqa: S603 - reviewed fixed interpreter boundary"
_KNOWN_ADAPTER_NAMES: Final = "KNOWN_ADAPTER_NAMES"
_FAKE_ADAPTER_MODULE: Final = "fake_adapter"
_ROADMAP: Final = "docs/superpowers/plans/2026-08-10-project-1-master-roadmap.md"
_VERIFICATION_GUIDE: Final = "docs/development/verification.md"
_README: Final = "README.md"
_WINDOWS_API: Final = "process_supervision/windows_api.py"
#: Plan section 9.6: the Stage 6 row's shape minus its schema-addition and flow clauses.
_STAGE7_ROADMAP_ROW: Final = (
    "| 7 — Windows Process Supervision | Approved and executed | Implementation "
    f"complete at `{STAGE7_IMPLEMENTATION_COMMIT}` | Complete; shell-free absolute "
    "argument-array launch with a fresh empty environment, bounded stdout and stderr "
    "readers, incremental protocol parsing, paired UTC and monotonic deadlines, "
    "heartbeat liveness, graceful and forced termination with Job Object process-tree "
    "cleanup, durable PID creation identity, path preflight, stale-invocation "
    "rejection, and restart reconciliation, with the 52-row Stage 6 contract matrix "
    "and the Windows platform cases driven through the production supervisor; no "
    "schema was added and the closed 35-schema registry is preserved byte-identical; "
    "the Stage 7 focused checks and status pins together with the Stage 7 boundary "
    "guard and this status were added by the separate Task 9 commit, which is not the "
    "implementation hash; verified offline on the complete verifier; GitNexus remains "
    "`DISABLED_WITH_EVIDENCE` with the manual source, reference, and diff fallback "
    "recorded; Stage 8 not started |"
)
_STAGE7_DEFERRED_ROW: Final = (
    "| 7 — Windows Process Supervision | Intentionally deferred until Stage 6 "
    "completion | Not started | Not evaluated |"
)
_STAGE8_ROADMAP_ROW: Final = (
    "| 8 — SQLite Persistence and Migrations | Intentionally deferred until Stages 3, "
    "5, and 7 completion | Not started | Not evaluated |"
)
#: The committed runtime rule of ``windows_api.py`` (declared reading 5), as the guide
#: states it, hard-wrapped at 80 columns.
_VERIFICATION_DESCENDANT_RULE: Final = "\n".join(
    (
        "The Windows controller keeps a Toolhelp candidate as a descendant only when",
        "its creation time is not earlier than its parent's recorded creation time, so",
        "a stale parent process identifier that now names a newer process is excluded",
        "while a creation in the same clock tick is admitted.",
    )
)
_DESCENDANT_RULE_PHRASE: Final = "not earlier than"
_DESCENDANT_RULE_RETIRED_PHRASE: Final = "later than its parent"
_NUMBER_WORDS: Final[Mapping[int, str]] = {10: "ten", 11: "eleven", 12: "twelve"}
_RETIRED_SUBPROCESS_IMPORTER_PHRASE: Final = "the ten `subprocess` importers"
#: Stage 8 negatives: the finalization, manifest and persistence names that stay
#: deferred.
_STAGE8_AND_LATER_NAMES: Final[tuple[str, ...]] = (
    "ArtifactFinalizer",
    "ArtifactRef",
    "ArtifactRepository",
    "CandidateArtifact",
    "CandidateArtifactRepository",
    "CandidateFinalization",
    "FinalizationResult",
    "ResultFinalizationRequest",
    "RunManifest",
)
_STAGE8_SHAPED_PATTERN: Final = re.compile(
    r"alembic|migration|\.db$|sqlite|sqlalchemy", re.IGNORECASE
)
_STAGE8_SCAN_ROOTS: Final[tuple[str, ...]] = ("src", "tests", "scripts", "schemas")
_STAGE8_SCAN_SKIP: Final = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache"})


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def _roots_by_module(repository_root: Path) -> dict[str, frozenset[str]]:
    source = repository_root / "src/crypto_lab"
    return {
        path.relative_to(source).as_posix(): frozenset(_imported_roots(_parse(path)))
        for path in _source_files(repository_root)
    }


def _confinement_violations(
    roots_by_module: Mapping[str, Iterable[str]],
    confinement: Mapping[str, frozenset[str]],
) -> list[str]:
    """Exact equality per root: an importer outside the named set and a named module
    that no longer imports the root are both violations."""
    violations: list[str] = []
    for root, allowed in confinement.items():
        importers = frozenset(
            module for module, roots in roots_by_module.items() if root in roots
        )
        for module in sorted(importers - allowed):
            violations.append(f"{module}: imports {root} outside its confinement")
        for module in sorted(allowed - importers):
            violations.append(f"{module}: no longer imports {root}")
    return violations


def _narrow_filesystem_violations(tree: ast.AST, label: str) -> list[str]:
    violations = [
        f"{label}: filesystem root {root}"
        for root in _imported_roots(tree)
        if root in _NARROW_FILESYSTEM_ROOTS
    ]
    aliases = _import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _resolved_qualified_name(node.func, aliases)
        if target in _FORBIDDEN_PATH_CALLS:
            violations.append(f"{label}:{node.lineno}: ambient path call {target}")
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _FORBIDDEN_PATH_METHODS
        ):
            violations.append(
                f"{label}:{node.lineno}: ambient path method .{node.func.attr}()"
            )
    return violations


def _popen_calls(tree: ast.AST) -> list[ast.Call]:
    aliases = _import_aliases(tree)
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _resolved_qualified_name(node.func, aliases) == "subprocess.Popen"
    ]


def _subprocess_call_targets(tree: ast.AST) -> list[str]:
    """Every resolved ``subprocess`` call target, sorted; an attribute that is not
    called (``subprocess.PIPE``, ``except subprocess.TimeoutExpired``) is not a call."""
    aliases = _import_aliases(tree)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _resolved_qualified_name(node.func, aliases)
        if target == "subprocess" or (
            target is not None and target.startswith("subprocess.")
        ):
            targets.append(target)
    return sorted(targets)


def _number_word(count: int) -> str:
    """The guide's count word for the ``subprocess`` importers, generated from the
    Stage 6 guard's constant so the prose cannot drift; a count outside the table
    fails by name rather than as a collection error."""
    word = _NUMBER_WORDS.get(count)
    assert word is not None, (
        f"no number word for {count} importers; extend _NUMBER_WORDS"
    )
    return word


def _subprocess_importer_phrase(count: int) -> str:
    return f"the {_number_word(count)} `subprocess` importers"


def _is_list_argv(node: ast.expr) -> bool:
    if isinstance(node, ast.List):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "list"
    )


def _keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_constant(node: ast.expr | None, value: object) -> bool:
    return (
        isinstance(node, ast.Constant)
        and type(node.value) is type(value)
        and node.value == value
    )


def _production_popen_violations(
    call: ast.Call, aliases: Mapping[str, str], source_line: str
) -> list[str]:
    """Plan sections 2.6 and 11: the reviewed shape of the one ``Popen`` in ``src``."""
    violations: list[str] = []
    if not call.args or not _is_list_argv(call.args[0]):
        violations.append("first argument is not a list argv")
    if len(call.args) != 1:
        violations.append("exactly one positional argument is required")
    keywords = frozenset(keyword.arg for keyword in call.keywords if keyword.arg)
    if keywords != _POPEN_KEYWORDS:
        violations.append(f"keywords are {sorted(keywords)}")
    if not _is_constant(_keyword_value(call, "shell"), False):
        violations.append("shell is not the constant False")
    env = _keyword_value(call, "env")
    if not (isinstance(env, ast.Dict) and not env.keys):
        violations.append("env is not the empty mapping literal")
    stdin = _keyword_value(call, "stdin")
    if stdin is None or _resolved_qualified_name(stdin, dict(aliases)) != (
        "subprocess.DEVNULL"
    ):
        violations.append("stdin is not subprocess.DEVNULL")
    for stream in ("stdout", "stderr"):
        value = _keyword_value(call, stream)
        if value is None or _resolved_qualified_name(value, dict(aliases)) != (
            "subprocess.PIPE"
        ):
            violations.append(f"{stream} is not subprocess.PIPE")
    if not _is_constant(_keyword_value(call, "close_fds"), True):
        violations.append("close_fds is not the constant True")
    if not _is_constant(_keyword_value(call, "bufsize"), 0):
        violations.append("bufsize is not the constant 0")
    flags = _keyword_value(call, "creationflags")
    if not (
        isinstance(flags, ast.BinOp)
        and isinstance(flags.op, ast.BitOr)
        and _resolved_qualified_name(flags.left, dict(aliases))
        == "subprocess.CREATE_NEW_PROCESS_GROUP"
        and isinstance(flags.right, ast.Name)
        and flags.right.id == _CREATE_SUSPENDED_NAME
    ):
        violations.append(
            "creationflags is not "
            "subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED"
        )
    if _POPEN_NOQA not in source_line:
        violations.append("the reviewed noqa text is missing from the call line")
    return violations


def _fake_popen_violations(call: ast.Call, source_line: str) -> list[str]:
    """Plan section 9.1: the fake's one child launch, a list argv, ``shell=False``."""
    violations: list[str] = []
    if not call.args or not isinstance(call.args[0], ast.List):
        violations.append("first argument is not a list literal")
    if not _is_constant(_keyword_value(call, "shell"), False):
        violations.append("shell is not the constant False")
    if _FAKE_POPEN_NOQA not in source_line:
        violations.append("the reviewed noqa text is missing from the call line")
    return violations


def _constant_bindings(tree: ast.AST, name: str) -> list[object]:
    """Every module-level binding of ``name`` to a constant."""
    values: list[object] = []
    for node in ast.walk(tree):
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        if (
            isinstance(target, ast.Name)
            and target.id == name
            and isinstance(value, ast.Constant)
        ):
            values.append(value.value)
    return values


def _imports_name_from(tree: ast.AST, module: str, name: str) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == module
        and any(alias.name == name for alias in node.names)
        for node in ast.walk(tree)
    )


def _package_direction_violations(
    tree: ast.AST, label: str, module_package: str, prohibited: Iterable[str]
) -> list[str]:
    violations: list[str] = []
    for name in _imported_names(tree, module_package):
        for package in prohibited:
            if name == package or name.startswith(f"{package}."):
                violations.append(f"{label}: prohibited import {name}")
    return violations


def _sys_path_inserts(tree: ast.AST) -> list[ast.Call]:
    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if (
            isinstance(function, ast.Attribute)
            and function.attr == "insert"
            and isinstance(function.value, ast.Attribute)
            and function.value.attr == "path"
            and isinstance(function.value.value, ast.Name)
            and function.value.value.id == "sys"
        ):
            found.append(node)
    return found


def _known_adapter_name_stores(tree: ast.AST) -> list[ast.AST]:
    """Every statement that stores into ``fake_adapter.KNOWN_ADAPTER_NAMES[...]`` or
    rebinds the attribute itself."""
    found: list[ast.AST] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            continue
        targets: list[ast.expr] = (
            list(node.targets) if isinstance(node, ast.Assign) else [node.target]
        )
        for target in targets:
            attribute = target.value if isinstance(target, ast.Subscript) else target
            if (
                isinstance(attribute, ast.Attribute)
                and attribute.attr == _KNOWN_ADAPTER_NAMES
                and isinstance(attribute.value, ast.Name)
                and attribute.value.id == _FAKE_ADAPTER_MODULE
            ):
                found.append(node)
    return found


def _docstring_violations(tree: ast.Module, label: str) -> list[str]:
    docstring = ast.get_docstring(tree) or ""
    return [
        f"{label}: module docstring contains {substring!r}"
        for substring in _DOCSTRING_DENYLIST
        if substring in docstring
    ]


def _stage8_shaped_paths(repository_root: Path) -> list[str]:
    found: list[str] = []
    candidates: list[Path] = [
        path for path in repository_root.iterdir() if path.is_file()
    ]
    for root in _STAGE8_SCAN_ROOTS:
        candidates.extend(
            path
            for path in (repository_root / root).rglob("*")
            if not _STAGE8_SCAN_SKIP.intersection(path.parts)
        )
    for path in candidates:
        relative = path.relative_to(repository_root).as_posix()
        if _STAGE8_SHAPED_PATTERN.search(relative):
            found.append(relative)
    return sorted(found)


def _defined_names(tree: ast.AST) -> frozenset[str]:
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    )


def _read(repository_root: Path, relative: str) -> str:
    return (repository_root / relative).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Source-tree facts
# --------------------------------------------------------------------------


def test_the_stage_seven_source_files_are_exactly_the_twelve_plan_paths(
    repository_root: Path,
) -> None:
    assert len(STAGE7_SOURCE_FILES) == 12
    assert len(set(STAGE7_SOURCE_FILES)) == 12
    assert set(STAGE7_SOURCE_FILES) <= _ALLOWED_SOURCE_FILES
    assert set(STAGE7_SOURCE_FILES).isdisjoint(STAGE5_SOURCE_FILES)
    assert set(STAGE7_SOURCE_FILES).isdisjoint(STAGE6_SOURCE_FILES)
    scanned = {*STAGE7_SOURCE_FILES, _PACKAGE_INIT}
    assert _FULL_SCAN_MODULES | _PATHLIB_MODULES == scanned
    assert _FULL_SCAN_MODULES.isdisjoint(_PATHLIB_MODULES)
    for relative_path in (*STAGE7_SOURCE_FILES, _PACKAGE_INIT):
        assert (repository_root / "src/crypto_lab" / relative_path).is_file()


def test_each_stage_seven_import_root_is_confined_to_its_named_modules(
    repository_root: Path,
) -> None:
    roots_by_module = _roots_by_module(repository_root)
    assert _confinement_violations(roots_by_module, _ROOT_CONFINEMENT) == []
    # The five roots are exactly the ones plan 2.6 adds to the Stage 3 allowlist.
    five_roots = {"threading", "queue", "ctypes", "subprocess", "asyncio"}
    assert set(_ROOT_CONFINEMENT) == five_roots


def test_stage_seven_modules_touch_neither_environment_clock_infrastructure_nor_shell(
    repository_root: Path,
) -> None:
    violations: list[str] = []
    for relative_path in (*STAGE7_SOURCE_FILES, _PACKAGE_INIT):
        tree = _parse(repository_root / "src/crypto_lab" / relative_path)
        violations.extend(_environment_access_violations(tree, relative_path))
        violations.extend(_infrastructure_violations(tree, relative_path))
        violations.extend(_ambient_clock_violations(tree, relative_path))
        violations.extend(
            _shell_violations(
                tree, relative_path, subprocess_importer=relative_path == _POPEN_MODULE
            )
        )
    assert violations == []


def test_stage_seven_modules_touch_the_filesystem_only_where_the_plan_places_it(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    for relative_path in (*STAGE7_SOURCE_FILES, _PACKAGE_INIT):
        tree = _parse(source / relative_path)
        assert _narrow_filesystem_violations(tree, relative_path) == []
    for relative_path in sorted(_FULL_SCAN_MODULES):
        tree = _parse(source / relative_path)
        assert _filesystem_violations(tree, relative_path) == []
    for relative_path in sorted(_PATHLIB_MODULES):
        tree = _parse(source / relative_path)
        residue = _filesystem_violations(tree, relative_path)
        pathlib_root = f"{relative_path}: filesystem or environment root pathlib"
        open_calls = [item for item in residue if item.endswith("open() call")]
        assert pathlib_root in residue
        assert set(residue) == {pathlib_root, *open_calls}
        expected_open_calls = (
            _WRITE_BOUNDARY_OPEN_CALLS if relative_path == _WRITE_BOUNDARY_MODULE else 0
        )
        assert len(open_calls) == expected_open_calls


def test_the_one_popen_call_in_src_has_exactly_the_reviewed_launch_shape(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    calls_by_module: dict[str, list[ast.Call]] = {}
    for path in _source_files(repository_root):
        label = path.relative_to(source).as_posix()
        calls = _popen_calls(_parse(path))
        if calls:
            calls_by_module[label] = calls
    assert set(calls_by_module) == {_POPEN_MODULE}
    (call,) = calls_by_module[_POPEN_MODULE]
    module_path = source / _POPEN_MODULE
    tree = _parse(module_path)
    source_line = module_path.read_text(encoding="utf-8").splitlines()[call.lineno - 1]
    assert _production_popen_violations(call, _import_aliases(tree), source_line) == []
    # The exempted module has exactly one subprocess call at all, so no second launch
    # path (run, check_output, call) can appear beside the reviewed Popen.
    assert _subprocess_call_targets(tree) == ["subprocess.Popen"]
    assert _imports_name_from(
        tree, f"{_PROCESS_SUPERVISION_PACKAGE}.models", _CREATE_SUSPENDED_NAME
    )
    assert _constant_bindings(
        _parse(source / _CREATE_SUSPENDED_MODULE), _CREATE_SUSPENDED_NAME
    ) == [_CREATE_SUSPENDED_VALUE]


def test_process_supervision_and_experiments_keep_the_dependency_direction(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    violations: list[str] = []
    scanned = 0
    for path in sorted((source / "process_supervision").rglob("*.py")):
        label = path.relative_to(source).as_posix()
        tree = _parse(path)
        violations.extend(
            _package_direction_violations(
                tree, label, _module_package(label), _PROHIBITED_FOR_PROCESS_SUPERVISION
            )
        )
        violations.extend(_stage6_test_double_violations(tree, label))
        scanned += 1
    for path in sorted((source / "experiments").rglob("*.py")):
        label = path.relative_to(source).as_posix()
        violations.extend(
            _package_direction_violations(
                _parse(path), label, _module_package(label), _PROHIBITED_FOR_EXPERIMENTS
            )
        )
        scanned += 1
    assert violations == []
    assert scanned == 12 + 11


def test_the_word_sandbox_appears_only_in_the_package_docstring_negative_sentence(
    repository_root: Path,
) -> None:
    source = repository_root / "src/crypto_lab"
    mentions = {
        relative_path: _read(repository_root, f"src/crypto_lab/{relative_path}")
        .lower()
        .count(_SANDBOX)
        for relative_path in (*STAGE7_SOURCE_FILES, _PACKAGE_INIT)
    }
    assert {module for module, count in mentions.items() if count} == {_PACKAGE_INIT}
    assert mentions[_PACKAGE_INIT] == 1
    docstring = ast.get_docstring(_parse(source / _PACKAGE_INIT)) or ""
    assert _SANDBOX_NEGATIVE_SENTENCE in docstring
    assert docstring.lower().count(_SANDBOX) == 1


def test_no_stage_seven_module_docstring_contains_a_purity_scan_substring(
    repository_root: Path,
) -> None:
    violations: list[str] = []
    for relative_path in (*STAGE7_SOURCE_FILES, _PACKAGE_INIT):
        tree = _parse(repository_root / "src/crypto_lab" / relative_path)
        assert ast.get_docstring(tree), relative_path
        violations.extend(_docstring_violations(tree, relative_path))
    assert violations == []


# --------------------------------------------------------------------------
# Test-tree facts
# --------------------------------------------------------------------------


def test_the_stage_seven_fake_has_exactly_its_reviewed_shape(
    repository_root: Path,
) -> None:
    path = repository_root / _SUPERVISION_FAKE
    tree = _parse(path)
    assert frozenset(_imported_roots(tree)) == _SUPERVISION_FAKE_ROOTS
    assert "crypto_lab" not in _imported_roots(tree)
    assert len(_sys_path_inserts(tree)) == 1
    assert len(_known_adapter_name_stores(tree)) == 1
    (call,) = _popen_calls(tree)
    source_line = path.read_text(encoding="utf-8").splitlines()[call.lineno - 1]
    assert _fake_popen_violations(call, source_line) == []
    assert _SUPERVISION_FAKE in _SUBPROCESS_IMPORTERS
    assert _shell_violations(tree, _SUPERVISION_FAKE, subprocess_importer=True) == []


# --------------------------------------------------------------------------
# Completion-status facts
# --------------------------------------------------------------------------


def test_the_roadmap_records_stage_seven_complete_and_stage_eight_not_started(
    repository_root: Path,
) -> None:
    roadmap = _read(repository_root, _ROADMAP)
    readme = _read(repository_root, _README)
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    assert _STAGE7_ROADMAP_ROW in roadmap
    assert _STAGE7_DEFERRED_ROW not in roadmap
    assert _STAGE8_ROADMAP_ROW in roadmap
    assert f"**Approved detailed implementation plan:** `{STAGE7_PLAN}`." in roadmap
    assert f"**Planned detailed implementation plan:** `{STAGE7_PLAN}`." not in roadmap
    assert "Stage 7 not started" not in roadmap
    assert "Stage 7 has not started" not in readme
    assert "Stage 7 is not started" not in guide
    # The implementation hash is the Task 8 commit, written exactly once per surface.
    assert roadmap.count(STAGE7_IMPLEMENTATION_COMMIT) == 1
    assert readme.count(STAGE7_IMPLEMENTATION_COMMIT) == 1
    assert guide.count(STAGE7_IMPLEMENTATION_COMMIT) == 1
    # No surface may claim Stage 8 progress or a Stage 8 completion.
    for text in (roadmap, readme, guide):
        assert "Stage 8 complete" not in text
        assert "Stage 8 is complete" not in text
        assert "Stage 8 has started" not in text
    assert "Stages 1-8" not in readme
    assert "Stages 1 through 8" not in roadmap


def test_the_guide_states_the_committed_descendant_creation_time_rule(
    repository_root: Path,
) -> None:
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    api = _read(repository_root, f"src/crypto_lab/{_WINDOWS_API}")
    assert _VERIFICATION_DESCENDANT_RULE in guide
    assert _DESCENDANT_RULE_PHRASE in api
    assert _DESCENDANT_RULE_RETIRED_PHRASE not in guide
    assert _DESCENDANT_RULE_RETIRED_PHRASE not in api
    assert _DESCENDANT_RULE_RETIRED_PHRASE not in _read(repository_root, _README)


def test_the_guide_names_the_subprocess_importer_count_the_guard_pins(
    repository_root: Path,
) -> None:
    guide = _read(repository_root, _VERIFICATION_GUIDE)
    assert len(_SUBPROCESS_IMPORTERS) == 11
    assert _subprocess_importer_phrase(len(_SUBPROCESS_IMPORTERS)) in guide
    assert _RETIRED_SUBPROCESS_IMPORTER_PHRASE not in guide


def test_no_documentation_surface_claims_a_sandbox(repository_root: Path) -> None:
    """Spec 15.4: the Job Object is a cleanup mechanism; README and the guide never use
    the word at all (the roadmap names it only inside the Stage 7 exclusion list)."""
    assert _SANDBOX not in _read(repository_root, _VERIFICATION_GUIDE).lower()
    assert _SANDBOX not in _read(repository_root, _README).lower()


def test_stage_eight_persistence_has_not_started(repository_root: Path) -> None:
    persistence = repository_root / "src/crypto_lab/persistence"
    entries = sorted(
        path.name
        for path in persistence.iterdir()
        if path.name not in _STAGE8_SCAN_SKIP
    )
    assert entries == ["__init__.py"]
    tree = _parse(persistence / "__init__.py")
    assert len(tree.body) == 1
    (statement,) = tree.body
    assert isinstance(statement, ast.Expr)
    assert isinstance(statement.value, ast.Constant)
    assert isinstance(statement.value.value, str)
    assert _stage8_shaped_paths(repository_root) == []
    defined: set[str] = set()
    for path in _source_files(repository_root):
        defined |= _defined_names(_parse(path))
    for name in _STAGE8_AND_LATER_NAMES:
        assert name in _DEFERRED_DEFINITIONS
        assert name not in defined


# --------------------------------------------------------------------------
# Planted-violation controls
# --------------------------------------------------------------------------


def test_the_confinement_scan_detects_a_stray_importer_and_a_lost_import() -> None:
    confinement = {"queue": frozenset({"a.py"}), "ctypes": frozenset({"b.py"})}
    clean = {"a.py": {"queue"}, "b.py": {"ctypes"}, "c.py": {"re"}}
    assert _confinement_violations(clean, confinement) == []
    stray = {"a.py": {"queue"}, "b.py": {"ctypes"}, "c.py": {"queue"}}
    assert _confinement_violations(stray, confinement) == [
        "c.py: imports queue outside its confinement"
    ]
    lost = {"a.py": {"queue"}, "b.py": {"re"}}
    assert _confinement_violations(lost, confinement) == [
        "b.py: no longer imports ctypes"
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import os\n",
        "import sys\n",
        "import shutil\n",
        "import tempfile\n",
        "import stat\n",
        "import io\n",
        "import glob\n",
        "from pathlib import Path\nPath.cwd()\n",
        "from pathlib import Path\nPath.home()\n",
        "from pathlib import Path\nPath('x').expanduser()\n",
        "import pathlib\npathlib.Path.cwd()\n",
    ],
)
def test_the_narrow_filesystem_scan_detects_each_shape(source: str) -> None:
    assert _narrow_filesystem_violations(ast.parse(source), "probe.py") != []


def test_the_narrow_filesystem_scan_allows_pure_path_arithmetic() -> None:
    source = (
        "from pathlib import Path, PureWindowsPath\n"
        "def f(root):\n"
        "    return PureWindowsPath(root) / 'request.json', Path(root).exists()\n"
    )
    assert _narrow_filesystem_violations(ast.parse(source), "probe.py") == []


_REVIEWED_POPEN = (
    "import subprocess\n"
    "from crypto_lab.process_supervision.models import CREATE_SUSPENDED\n"
    "popen = subprocess.Popen(  {noqa}\n"
    "    list(argv),\n"
    "    shell=False,\n"
    "    env={{}},\n"
    "    cwd=c,\n"
    "    stdin=subprocess.DEVNULL,\n"
    "    stdout=subprocess.PIPE,\n"
    "    stderr=subprocess.PIPE,\n"
    "    bufsize=0,\n"
    "    close_fds=True,\n"
    "    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,\n"
    ")\n"
)


def _reviewed_popen(**replacements: str) -> tuple[ast.Call, dict[str, str], str]:
    source = _REVIEWED_POPEN.format(noqa=_POPEN_NOQA)
    for old, new in replacements.items():
        assert old in source
        source = source.replace(old, new)
    tree = ast.parse(source)
    (call,) = _popen_calls(tree)
    line = source.splitlines()[call.lineno - 1]
    return call, _import_aliases(tree), line


def test_the_production_popen_scan_accepts_the_reviewed_shape() -> None:
    call, aliases, line = _reviewed_popen()
    assert _production_popen_violations(call, aliases, line) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("list(argv)", "'cmd.exe /c dir'"),
        ("list(argv)", "argv"),
        ("shell=False", "shell=True"),
        ("env={},", "env=None,"),
        ("env={},", "env={'PATH': p},"),
        ("    env={},\n", ""),
        ("stdin=subprocess.DEVNULL", "stdin=None"),
        ("stdout=subprocess.PIPE", "stdout=subprocess.DEVNULL"),
        ("stderr=subprocess.PIPE", "stderr=subprocess.STDOUT"),
        ("close_fds=True", "close_fds=False"),
        ("bufsize=0", "bufsize=1"),
        (" | CREATE_SUSPENDED", ""),
        ("subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED", "CREATE_SUSPENDED"),
        ("CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED", "CREATE_NEW_PROCESS_GROUP | 4"),
        ("    bufsize=0,\n", "    bufsize=0,\n    text=True,\n"),
        (_POPEN_NOQA, "# noqa: S603"),
    ],
)
def test_the_production_popen_scan_detects_each_mutation(old: str, new: str) -> None:
    call, aliases, line = _reviewed_popen(**{old: new})
    assert _production_popen_violations(call, aliases, line) != []


def test_the_popen_locator_resolves_aliases_and_ignores_other_calls() -> None:
    aliased = ast.parse("import subprocess as sp\nsp.Popen(['x'])\nsp.run(['x'])\n")
    assert len(_popen_calls(aliased)) == 1
    assert _subprocess_call_targets(aliased) == ["subprocess.Popen", "subprocess.run"]
    imported = ast.parse("from subprocess import Popen\nPopen(['x'])\n")
    assert len(_popen_calls(imported)) == 1
    unrelated = ast.parse("class Popen: ...\nPopen()\nsubprocess = None\n")
    assert _popen_calls(unrelated) == []
    attributes_only = ast.parse(
        "import subprocess\n"
        "flag = subprocess.PIPE\n"
        "try:\n    pass\nexcept subprocess.TimeoutExpired:\n    pass\n"
    )
    assert _subprocess_call_targets(attributes_only) == []


def test_the_number_word_lookup_fails_by_name_outside_its_table() -> None:
    assert _subprocess_importer_phrase(11) == "the eleven `subprocess` importers"
    with pytest.raises(AssertionError, match="no number word for 13 importers"):
        _number_word(13)


def test_the_fake_popen_scan_detects_each_mutation() -> None:
    reviewed = (
        "import subprocess\n"
        f"subprocess.Popen(  {_FAKE_POPEN_NOQA}\n"
        "    [a, b],\n"
        "    shell=False,\n"
        ")\n"
    )
    tree = ast.parse(reviewed)
    (call,) = _popen_calls(tree)
    line = reviewed.splitlines()[call.lineno - 1]
    assert _fake_popen_violations(call, line) == []
    for mutant in (
        reviewed.replace("[a, b]", "'x'"),
        reviewed.replace("[a, b]", "list(a)"),
        reviewed.replace("shell=False", "shell=True"),
        reviewed.replace("    shell=False,\n", ""),
        reviewed.replace(_FAKE_POPEN_NOQA, "# noqa: S603"),
    ):
        mutant_tree = ast.parse(mutant)
        (mutant_call,) = _popen_calls(mutant_tree)
        mutant_line = mutant.splitlines()[mutant_call.lineno - 1]
        assert _fake_popen_violations(mutant_call, mutant_line) != []


def test_the_constant_binding_scan_reads_annotated_and_plain_bindings() -> None:
    tree = ast.parse(
        "from typing import Final\n"
        "CREATE_SUSPENDED: Final = 0x00000004\n"
        "OTHER = 4\n"
        "def f():\n    CREATE_SUSPENDED = 8\n"
    )
    assert _constant_bindings(tree, "CREATE_SUSPENDED") == [4, 8]
    assert _constant_bindings(tree, "OTHER") == [4]
    assert _constant_bindings(tree, "MISSING") == []
    models_module = "crypto_lab.process_supervision.models"
    assert _imports_name_from(
        ast.parse(f"from {models_module} import A, CREATE_SUSPENDED\n"),
        models_module,
        "CREATE_SUSPENDED",
    )
    assert not _imports_name_from(
        ast.parse("from crypto_lab.process_supervision import models\n"),
        "crypto_lab.process_supervision.models",
        "CREATE_SUSPENDED",
    )


@pytest.mark.parametrize(
    ("source", "package"),
    [
        ("from crypto_lab.experiments import ports\n", _PROCESS_SUPERVISION_PACKAGE),
        ("import crypto_lab.configuration.models\n", _PROCESS_SUPERVISION_PACKAGE),
        ("from crypto_lab import persistence\n", _PROCESS_SUPERVISION_PACKAGE),
        ("from crypto_lab.cli.main import main\n", _PROCESS_SUPERVISION_PACKAGE),
        ("from ..experiments import ports\n", _PROCESS_SUPERVISION_PACKAGE),
        ("from crypto_lab.process_supervision import ports\n", _EXPERIMENTS_PACKAGE),
        ("from ..process_supervision.models import X\n", _EXPERIMENTS_PACKAGE),
    ],
)
def test_the_direction_scan_detects_each_prohibited_import(
    source: str, package: str
) -> None:
    prohibited = (
        _PROHIBITED_FOR_PROCESS_SUPERVISION
        if package == _PROCESS_SUPERVISION_PACKAGE
        else _PROHIBITED_FOR_EXPERIMENTS
    )
    violations = _package_direction_violations(
        ast.parse(source), "probe.py", package, prohibited
    )
    assert violations != []


def test_the_direction_scan_allows_the_permitted_edges() -> None:
    source = (
        "from crypto_lab.adapters.commands import AdapterCommand\n"
        "from crypto_lab.domain.results import Result\n"
        "from crypto_lab.process_supervision.models import LaunchSpecification\n"
        "from .ports import ProcessController\n"
    )
    assert (
        _package_direction_violations(
            ast.parse(source),
            "probe.py",
            _PROCESS_SUPERVISION_PACKAGE,
            _PROHIBITED_FOR_PROCESS_SUPERVISION,
        )
        == []
    )


def test_the_fake_shape_scans_count_exactly() -> None:
    tree = ast.parse(
        "import sys\n"
        "sys.path.insert(0, here)\n"
        "sys.path.append(there)\n"
        "import fake_adapter\n"
        "fake_adapter.KNOWN_ADAPTER_NAMES[command] = names\n"
        "other.KNOWN_ADAPTER_NAMES[command] = names\n"
        "value = fake_adapter.KNOWN_ADAPTER_NAMES[command]\n"
    )
    assert len(_sys_path_inserts(tree)) == 1
    assert len(_known_adapter_name_stores(tree)) == 1
    doubled = ast.parse(
        "import fake_adapter\n"
        "fake_adapter.KNOWN_ADAPTER_NAMES[a] = x\n"
        "fake_adapter.KNOWN_ADAPTER_NAMES = {}\n"
        "fake_adapter.KNOWN_ADAPTER_NAMES[b] |= y\n"
    )
    assert len(_known_adapter_name_stores(doubled)) == 3
    assert _sys_path_inserts(ast.parse("import sys\nsys.path[:0] = [here]\n")) == []


@pytest.mark.parametrize("substring", _DOCSTRING_DENYLIST)
def test_the_docstring_scan_detects_each_denied_substring(substring: str) -> None:
    tree = ast.parse(f'"""Reads {substring} at import time."""\n')
    assert _docstring_violations(tree, "probe.py") == [
        f"probe.py: module docstring contains {substring!r}"
    ]


def test_the_docstring_scan_ignores_code_and_allows_clean_prose() -> None:
    code_only = ast.parse('"""Clean."""\nimport random\nx = "os.environ"\n')
    assert _docstring_violations(code_only, "probe.py") == []
    assert _docstring_violations(ast.parse("x = 1\n"), "probe.py") == []


def test_the_stage_eight_path_scan_detects_each_shape(tmp_path: Path) -> None:
    for root in _STAGE8_SCAN_ROOTS:
        (tmp_path / root).mkdir()
    assert _stage8_shaped_paths(tmp_path) == []
    (tmp_path / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")
    (tmp_path / "src/crypto_lab").mkdir(parents=True)
    (tmp_path / "src/crypto_lab/persistence_sqlite.py").write_text("", encoding="utf-8")
    (tmp_path / "tests/migrations").mkdir()
    (tmp_path / "tests/migrations/test_x.py").write_text("", encoding="utf-8")
    (tmp_path / "schemas/registry.db").write_text("", encoding="utf-8")
    (tmp_path / "scripts/__pycache__").mkdir()
    (tmp_path / "scripts/__pycache__/sqlalchemy.pyc").write_text("", encoding="utf-8")
    assert _stage8_shaped_paths(tmp_path) == [
        "alembic.ini",
        "schemas/registry.db",
        "src/crypto_lab/persistence_sqlite.py",
        "tests/migrations",
        "tests/migrations/test_x.py",
    ]


def test_the_defined_name_scan_sees_classes_and_functions() -> None:
    tree = ast.parse(
        "class RunManifest: ...\ndef place_order(): ...\nasync def g(): ...\n"
    )
    assert _defined_names(tree) == {"RunManifest", "place_order", "g"}
    assert _defined_names(ast.parse("x = 1\n")) == frozenset()
