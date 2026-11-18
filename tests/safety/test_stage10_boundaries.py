"""Stage 10 source-level safety guards (Stage 10 plan Task 1, the guard foundation).

Task 1 pins the facts its two modules introduce: ``STAGE10_SOURCE_FILES`` is exactly
the cumulative Stage 10 module set; the three runtime roots ``time``, ``secrets`` and
``signal`` are imported by ``cli/runtime.py`` alone, and ``ctypes`` by that module
beside the Stage 7 ``process_supervision/windows_api.py``; no other module reaches
those roots through the runtime module; neither module does clock, entropy, native
binding or signal work while it is imported; and ``experiments/application_ports.py``
is inward only. Every scan is static and AST-based and carries planted-violation
controls that run through the same scanner as the real tree, because a guard that
cannot fail is not a guard.

Declared readings, so nothing is inferred silently:

- "Stage 10 module" means exactly the paths in ``STAGE10_SOURCE_FILES``, in task
  order (plan section 6.1); later tasks append and no earlier stage's set changes.
  Planted labels such as ``cli/probe.py`` are synthetic inputs to the scanners, never
  files on disk.
- Root confinement is exact equality per root (the Stage 7 scanner): an importer
  outside the named set and a named module that stops importing the root both fail.
  The runtime module's whole import-root set is pinned too, so no other root (``os``,
  ``io``, ``threading``, ``types`` among them) can join it silently.
- "Reaching a root through the runtime module" is any attribute chain that resolves
  to ``crypto_lab.cli.runtime.<root>`` and any ``from crypto_lab.cli.runtime import
  <root>``, outside the runtime module itself.
- "Import-time work" is a call (or a read through a ``ctypes`` library loader) that
  resolves to a clock, entropy, native-binding or signal-registration member while
  the module body runs: module and class bodies, decorators, base classes and
  default values, never a function or lambda body. It is the static complement of
  the behavioural fresh-import probe in ``tests/unit/cli/test_runtime.py``.
- "Inward only" means the ports module imports ``domain``, ``adapters`` and the
  Stage 5 ``experiments.ports`` alone among first-party modules, through absolute
  imports, and no concrete infrastructure root.

Task 2 (plan section 6.3) appends ``cli/startup.py`` to the set and pins its whole
import-root set and its exact first-party module set beside the Task 1 modules. It
also pins two negative properties of the startup coordinator, each with planted
controls through the same scanner: it reaches the artifact reconciler, the
migration runner and every other first-party module through public names only --
no imported or attribute-accessed name with a leading underscore -- and it exposes
no migration-script override: no parameter, keyword or attribute named
``script_location`` appears in it.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Final

from test_stage3_boundaries import (
    _ALLOWED_SOURCE_FILES,
    _import_aliases,
    _imported_roots,
    _resolved_qualified_name,
)
from test_stage5_boundaries import (
    STAGE5_SOURCE_FILES,
    _imported_names,
    _module_package,
    _parse,
)
from test_stage6_boundaries import STAGE6_SOURCE_FILES
from test_stage7_boundaries import (
    STAGE7_SOURCE_FILES,
    _confinement_violations,
    _roots_by_module,
)
from test_stage8_boundaries import STAGE8_SOURCE_FILES

#: Plan section 6.1: the source modules Stage 10 adds, in task order (Task 1: two;
#: Task 2: the startup coordinator).
STAGE10_SOURCE_FILES: Final[tuple[str, ...]] = (
    "cli/runtime.py",
    "experiments/application_ports.py",
    "cli/startup.py",
    "experiments/application.py",
)
_RUNTIME_MODULE: Final = "cli/runtime.py"
_STARTUP_MODULE: Final = "cli/startup.py"
_APPLICATION_MODULE: Final = "experiments/application.py"
_RUNTIME_PACKAGE: Final = "crypto_lab.cli.runtime"
_APPLICATION_PORTS_MODULE: Final = "experiments/application_ports.py"
_WINDOWS_API_MODULE: Final = "process_supervision/windows_api.py"
#: Plan section 2.6: the three roots Task 1 adds, and ``ctypes``'s two importers.
_RUNTIME_ONLY_ROOTS: Final = frozenset({"secrets", "signal", "time"})
_RUNTIME_ROOT_CONFINEMENT: Final[Mapping[str, frozenset[str]]] = {
    "secrets": frozenset({_RUNTIME_MODULE}),
    "signal": frozenset({_RUNTIME_MODULE}),
    "time": frozenset({_RUNTIME_MODULE}),
    "ctypes": frozenset({_WINDOWS_API_MODULE, _RUNTIME_MODULE}),
}
#: The complete import-root sets of the Stage 10 modules (Task 1: two; Task 2: one).
_MODULE_IMPORT_ROOTS: Final[Mapping[str, frozenset[str]]] = {
    _RUNTIME_MODULE: frozenset(
        {
            "__future__",
            "collections",
            "contextlib",
            "crypto_lab",
            "ctypes",
            "dataclasses",
            "datetime",
            "enum",
            "pathlib",
            "secrets",
            "signal",
            "time",
            "typing",
            "uuid",
        }
    ),
    _APPLICATION_PORTS_MODULE: frozenset(
        {"__future__", "crypto_lab", "pydantic", "typing"}
    ),
    _STARTUP_MODULE: frozenset(
        {
            "__future__",
            "collections",
            "crypto_lab",
            "dataclasses",
            "enum",
            "pathlib",
            "typing",
        }
    ),
    _APPLICATION_MODULE: frozenset(
        {
            "__future__",
            "collections",
            "contextlib",
            "copy",
            "crypto_lab",
            "datetime",
            "pydantic",
            "typing",
        }
    ),
}
#: Plan section 6.3 (Task 2): the exact first-party modules the startup coordinator
#: composes -- the public artifact reconciler, the Task 1 runtime and ports, the
#: normal and maintenance openers and the schema registry, nothing else.
_STARTUP_IMPORTS: Final = frozenset(
    {
        "crypto_lab.artifacts.hashing",
        "crypto_lab.artifacts.journal",
        "crypto_lab.artifacts.models",
        "crypto_lab.artifacts.ports",
        "crypto_lab.artifacts.recovery",
        "crypto_lab.artifacts.store",
        "crypto_lab.cli.runtime",
        "crypto_lab.domain.command_invocation",
        "crypto_lab.domain.diagnostics",
        "crypto_lab.domain.engine_run",
        "crypto_lab.domain.lifecycle",
        "crypto_lab.domain.ports",
        "crypto_lab.domain.results",
        "crypto_lab.experiments.application_ports",
        "crypto_lab.persistence.database",
        "crypto_lab.persistence.diagnostics",
        "crypto_lab.persistence.migration_runner",
        "crypto_lab.process_supervision.models",
        "crypto_lab.process_supervision.ports",
        "crypto_lab.schema_registry",
    }
)
_SCRIPT_OVERRIDE: Final = "script_location"
#: Plan section 6.11: roots neither Task 1 module may import.
_STAGE10_DENIED_ROOTS: Final = frozenset(
    {
        "asyncio",
        "io",
        "logging",
        "msvcrt",
        "os",
        "queue",
        "random",
        "shutil",
        "stat",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
        "types",
    }
)
#: Resolved names whose call while a module body runs is import-time work.
_IMPORT_TIME_CALLS: Final = frozenset(
    {
        "datetime.datetime.now",
        "datetime.datetime.utcnow",
        "datetime.datetime.today",
        "datetime.date.today",
        "uuid.uuid1",
        "uuid.uuid4",
        "os.urandom",
        "ctypes.WinDLL",
        "ctypes.CDLL",
        "ctypes.OleDLL",
        "ctypes.PyDLL",
        "signal.signal",
        "signal.set_wakeup_fd",
        "signal.raise_signal",
    }
)
#: Prefixes: any member of these modules, and any read through a library loader.
_IMPORT_TIME_PREFIXES: Final = ("time.", "secrets.", "random.")
_LIBRARY_LOADER_PREFIXES: Final = (
    "ctypes.windll.",
    "ctypes.cdll.",
    "ctypes.oledll.",
    "ctypes.pydll.",
)
#: Plan section 2.5: the first-party modules the inward ports may import, and the
#: packages and infrastructure roots they may never reach.
_APPLICATION_PORTS_IMPORTS: Final = frozenset(
    {
        "crypto_lab.adapters.commands",
        "crypto_lab.adapters.events",
        "crypto_lab.adapters.manifests",
        "crypto_lab.adapters.negotiation",
        "crypto_lab.domain.base",
        "crypto_lab.domain.command_invocation",
        "crypto_lab.domain.engine_run",
        "crypto_lab.domain.experiment",
        "crypto_lab.domain.identifiers",
        "crypto_lab.domain.ports",
        "crypto_lab.domain.results",
        "crypto_lab.domain.retry",
        "crypto_lab.experiments.ports",
    }
)
_INWARD_PERMITTED_PREFIXES: Final = (
    "crypto_lab.domain.",
    "crypto_lab.adapters.",
)
_INWARD_PERMITTED_MODULES: Final = frozenset({"crypto_lab.experiments.ports"})
_INWARD_DENIED_ROOTS: Final = frozenset(
    {
        "alembic",
        "asyncio",
        "ctypes",
        "io",
        "os",
        "pathlib",
        "queue",
        "secrets",
        "signal",
        "socket",
        "sqlalchemy",
        "sqlite3",
        "subprocess",
        "sys",
        "threading",
        "time",
    }
)


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def _source_path(repository_root: Path, label: str) -> Path:
    return repository_root / "src/crypto_lab" / label


def _runtime_reach_violations(tree: ast.AST, label: str) -> list[str]:
    """A runtime-only root (or ``ctypes``) reached through the runtime module."""
    if label == _RUNTIME_MODULE:
        return []
    reached_roots = _RUNTIME_ONLY_ROOTS | {"ctypes"}
    aliases = _import_aliases(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _RUNTIME_PACKAGE:
            for alias in node.names:
                if alias.name in reached_roots:
                    violations.append(
                        f"{label}:{node.lineno}: imports {alias.name} through the "
                        "runtime module"
                    )
        elif isinstance(node, ast.Attribute):
            resolved = _resolved_qualified_name(node, aliases)
            if resolved is None or not resolved.startswith(f"{_RUNTIME_PACKAGE}."):
                continue
            root = resolved.removeprefix(f"{_RUNTIME_PACKAGE}.").partition(".")[0]
            if root in reached_roots and resolved.count(".") == 3:
                violations.append(
                    f"{label}:{node.lineno}: reaches {root} through the runtime module"
                )
    return violations


def _import_time_nodes(tree: ast.Module) -> Iterator[ast.AST]:
    """Every node that runs while the module body runs (see the declared reading)."""
    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            if not isinstance(node, ast.Lambda):
                pending.extend(node.decorator_list)
            pending.extend(node.args.defaults)
            pending.extend(
                default for default in node.args.kw_defaults if default is not None
            )
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def _import_time_violations(tree: ast.Module, label: str) -> list[str]:
    aliases = _import_aliases(tree)
    violations: list[str] = []
    for node in _import_time_nodes(tree):
        if isinstance(node, ast.Call):
            resolved = _resolved_qualified_name(node.func, aliases)
            if resolved is not None and (
                resolved in _IMPORT_TIME_CALLS
                or resolved.startswith(_IMPORT_TIME_PREFIXES)
                or resolved.startswith(_LIBRARY_LOADER_PREFIXES)
            ):
                violations.append(f"{label}:{node.lineno}: import-time {resolved}")
        elif isinstance(node, ast.Attribute):
            resolved = _resolved_qualified_name(node, aliases)
            if resolved is not None and resolved.startswith(_LIBRARY_LOADER_PREFIXES):
                violations.append(f"{label}:{node.lineno}: import-time {resolved}")
    return sorted(set(violations))


def _private_reach_violations(tree: ast.AST, label: str) -> list[str]:
    """A first-party name with a leading underscore: imported (absolutely or
    relatively), or reached as an attribute of a first-party binding."""
    violations: list[str] = []
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (
            node.level > 0 or (node.module or "").startswith("crypto_lab")
        ):
            for alias in node.names:
                if alias.name.startswith("_"):
                    violations.append(
                        f"{label}:{node.lineno}: imports private {alias.name}"
                    )
                bound.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("crypto_lab"):
                    bound.add(alias.asname or alias.name.partition(".")[0])
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if not node.attr.startswith("_") or node.attr.startswith("__"):
            continue
        base: ast.expr = node.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name) and base.id in bound:
            violations.append(f"{label}:{node.lineno}: reaches private {node.attr}")
    return violations


def _script_override_violations(tree: ast.AST, label: str) -> list[str]:
    """Any parameter, keyword, attribute or name spelled ``script_location``."""
    violations: list[str] = []
    for node in ast.walk(tree):
        spelled = (
            (isinstance(node, ast.keyword) and node.arg == _SCRIPT_OVERRIDE)
            or (isinstance(node, ast.arg) and node.arg == _SCRIPT_OVERRIDE)
            or (isinstance(node, ast.Attribute) and node.attr == _SCRIPT_OVERRIDE)
            or (isinstance(node, ast.Name) and node.id == _SCRIPT_OVERRIDE)
        )
        if spelled:
            line = getattr(node, "lineno", 0)
            violations.append(f"{label}:{line}: migration script override")
    return violations


def _application_port_violations(tree: ast.AST, label: str) -> list[str]:
    violations = [
        f"{label}: infrastructure root {root}"
        for root in _imported_roots(tree)
        if root in _INWARD_DENIED_ROOTS
    ]
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level > 0:
            violations.append(f"{label}:{node.lineno}: relative import")
    for name in _imported_names(tree, _module_package(label)):
        if not name.startswith("crypto_lab"):
            continue
        if name in _INWARD_PERMITTED_MODULES or name.startswith(
            _INWARD_PERMITTED_PREFIXES
        ):
            continue
        violations.append(f"{label}: outward import {name}")
    return violations


# --------------------------------------------------------------------------
# The repository assertions
# --------------------------------------------------------------------------


def test_the_stage_ten_source_files_are_exactly_the_task_one_paths(
    repository_root: Path,
) -> None:
    """The name is historical: Task 2 appends the startup module, 2 -> 3."""
    assert len(STAGE10_SOURCE_FILES) == 4
    assert len(set(STAGE10_SOURCE_FILES)) == 4
    assert STAGE10_SOURCE_FILES[2] == _STARTUP_MODULE
    assert set(STAGE10_SOURCE_FILES) <= _ALLOWED_SOURCE_FILES
    for earlier in (
        STAGE5_SOURCE_FILES,
        STAGE6_SOURCE_FILES,
        STAGE7_SOURCE_FILES,
        STAGE8_SOURCE_FILES,
    ):
        assert set(STAGE10_SOURCE_FILES).isdisjoint(earlier)
    for relative_path in STAGE10_SOURCE_FILES:
        assert _source_path(repository_root, relative_path).is_file(), relative_path
    assert set(_MODULE_IMPORT_ROOTS) == set(STAGE10_SOURCE_FILES)


def test_runtime_roots_are_module_scoped(repository_root: Path) -> None:
    roots_by_module = _roots_by_module(repository_root)
    assert _confinement_violations(roots_by_module, _RUNTIME_ROOT_CONFINEMENT) == []
    for label, expected in _MODULE_IMPORT_ROOTS.items():
        assert roots_by_module[label] == expected, label
        assert expected.isdisjoint(_STAGE10_DENIED_ROOTS), label
    assert _RUNTIME_ONLY_ROOTS <= roots_by_module[_RUNTIME_MODULE]
    reach: list[str] = []
    for label in sorted(roots_by_module):
        tree = _parse(_source_path(repository_root, label))
        reach.extend(_runtime_reach_violations(tree, label))
    assert reach == []
    # Planted controls through the same confinement scan: a sibling importing a
    # runtime root, a planted module importing ctypes, a lost runtime import.
    planted_cases: tuple[tuple[str, str, bool], ...] = (
        ("cli/main.py", "time", True),
        ("cli/main.py", "secrets", True),
        ("cli/probe.py", "signal", True),
        ("cli/probe.py", "ctypes", True),
        ("experiments/application_ports.py", "time", True),
        (_RUNTIME_MODULE, "secrets", False),
    )
    for label, root, added in planted_cases:
        planted = {module: set(roots) for module, roots in roots_by_module.items()}
        holder = planted.setdefault(label, set())
        if added:
            holder.add(root)
        else:
            holder.discard(root)
        violations = _confinement_violations(planted, _RUNTIME_ROOT_CONFINEMENT)
        assert violations != [], (label, root)
        assert all(root in violation for violation in violations), violations
    # Planted sibling reaches through the runtime module, and the permitted shapes.
    planted_reaches = (
        "from crypto_lab.cli import runtime\nruntime.signal.signal(2, None)\n",
        (
            "import crypto_lab.cli.runtime\n"
            "crypto_lab.cli.runtime.secrets.token_bytes(1)\n"
        ),
        "from crypto_lab.cli.runtime import time\ntime.monotonic()\n",
        "from crypto_lab.cli import runtime as r\nk = r.ctypes.WinDLL\n",
    )
    for source in planted_reaches:
        tree = ast.parse(source)
        assert _runtime_reach_violations(tree, "cli/main.py") != [], source
        assert _runtime_reach_violations(tree, _RUNTIME_MODULE) == [], source
    permitted = (
        "from crypto_lab.cli.runtime import create_runtime_services\n"
        "from crypto_lab.cli import runtime\n"
        "services = runtime.create_runtime_services()\n"
    )
    assert _runtime_reach_violations(ast.parse(permitted), "cli/main.py") == []


def test_stage_ten_modules_do_no_import_time_work(repository_root: Path) -> None:
    for label in STAGE10_SOURCE_FILES:
        tree = _parse(_source_path(repository_root, label))
        assert _import_time_violations(tree, label) == [], label
    planted_work = (
        "from datetime import UTC, datetime\nSTARTED_AT = datetime.now(UTC)\n",
        "import datetime as dt\nTODAY = dt.date.today()\n",
        "import time\nSTARTED = time.monotonic()\n",
        "from time import perf_counter\nSTARTED = perf_counter()\n",
        "import secrets\nSEED = secrets.token_bytes(16)\n",
        "from uuid import uuid4\nIDENTITY = uuid4()\n",
        "import ctypes\nKERNEL32 = ctypes.WinDLL('kernel32')\n",
        "import ctypes\nKERNEL32 = ctypes.windll.kernel32\n",
        "import signal\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\n",
        "import time\ndef f(started=time.monotonic()):\n    return started\n",
        "import time\ndef f(*, started=time.time()):\n    return started\n",
        "import secrets\nclass Holder:\n    SEED = secrets.token_hex(8)\n",
        "import time\n@decorate(time.time())\ndef f():\n    return 1\n",
        "import time\nclass Holder(base(time.monotonic())):\n    pass\n",
        "import time\nREAD = (lambda started=time.monotonic(): started)\n",
    )
    for source in planted_work:
        planted = _import_time_violations(ast.parse(source), _RUNTIME_MODULE)
        assert len(planted) == 1, (source, planted)
    deferred = (
        "import time\ndef f():\n    return time.monotonic()\n",
        "import time\nclass Clock:\n    def read(self):\n        return time.time()\n",
        "import secrets\ndef f(entropy=secrets.token_bytes):\n    return entropy(16)\n",
        "import ctypes\nfrom ctypes import wintypes\nDWORD = wintypes.DWORD\n",
        "import ctypes\ndef bind():\n    return ctypes.WinDLL('kernel32')\n",
        "import signal\nSIGNALS = (signal.SIGINT, signal.SIGBREAK)\n",
        "import time\nREAD = lambda: time.monotonic()\n",
    )
    for source in deferred:
        assert _import_time_violations(ast.parse(source), _RUNTIME_MODULE) == [], source


def test_application_ports_are_inward_only(repository_root: Path) -> None:
    label = _APPLICATION_PORTS_MODULE
    tree = _parse(_source_path(repository_root, label))
    assert _application_port_violations(tree, label) == []
    first_party = {
        name
        for name in _imported_names(tree, _module_package(label))
        if name.startswith("crypto_lab")
    }
    assert first_party == _APPLICATION_PORTS_IMPORTS
    # Planted concrete imports fail the same scan as the real module.
    planted_imports = (
        ("from crypto_lab.persistence.database import SqliteDatabase\n", "persistence"),
        ("import crypto_lab.configuration.models\n", "configuration"),
        ("from crypto_lab import cli\n", "crypto_lab.cli"),
        ("from crypto_lab.cli.runtime import RuntimeClock\n", "crypto_lab.cli"),
        (
            "from crypto_lab.process_supervision.models import SupervisionOutcome\n",
            "process_supervision",
        ),
        ("from crypto_lab.artifacts.ports import ArtifactFinalizer\n", "artifacts"),
        ("from crypto_lab.audit.sink import AuditSink\n", "audit"),
        ("from crypto_lab.strategy.versioning import StrategyVersion\n", "strategy"),
        ("from crypto_lab.experiments.application import x\n", "application"),
        ("from ..persistence import database\n", "relative"),
        ("from . import scheduler\n", "relative"),
        ("import sqlalchemy\n", "sqlalchemy"),
        ("from pathlib import Path\n", "pathlib"),
        ("import asyncio\n", "asyncio"),
    )
    for source, expected in planted_imports:
        violations = _application_port_violations(ast.parse(source), label)
        assert violations != [], source
        assert any(expected in violation for violation in violations), violations
    legitimate = (
        "from crypto_lab.domain.results import Result\n"
        "from crypto_lab.adapters.commands import AdapterCommand\n"
        "from crypto_lab.experiments.ports import UnitOfWork\n"
        "from typing import Protocol\n"
        "from pydantic import model_validator\n"
    )
    assert _application_port_violations(ast.parse(legitimate), label) == []


def test_startup_reaches_first_party_modules_through_public_names_only(
    repository_root: Path,
) -> None:
    """Plan section 6.3 (Task 2): the startup coordinator calls the public recovery
    interface, never the private reconciler, and composes exactly its pinned
    first-party modules."""
    label = _STARTUP_MODULE
    tree = _parse(_source_path(repository_root, label))
    assert _private_reach_violations(tree, label) == []
    first_party = {
        name
        for name in _imported_names(tree, _module_package(label))
        if name.startswith("crypto_lab")
    }
    assert first_party == _STARTUP_IMPORTS
    planted = (
        "from crypto_lab.artifacts.recovery import _Reconciler\n",
        "from crypto_lab.artifacts import recovery\nrecovery._Reconciler(**k).run()\n",
        (
            "import crypto_lab.artifacts.recovery\n"
            "crypto_lab.artifacts.recovery._Reconciler\n"
        ),
        "from crypto_lab.artifacts import recovery as r\nr._drive(x)\n",
        "from crypto_lab.persistence.migration_runner import _admitting\n",
        (
            "from crypto_lab.persistence.database import SqliteDatabase\n"
            "SqliteDatabase._apply_revision_policy\n"
        ),
        "from .runtime import _kernel32\n",
    )
    for source in planted:
        assert _private_reach_violations(ast.parse(source), label) != [], source
    legitimate = (
        "from crypto_lab.artifacts.recovery import reconcile_finalization\n"
        "from crypto_lab.cli.runtime import DispatchOwner\n"
        "reconcile_finalization(phase='inventory')\n"
        "self._owner = owner\n"
        "phase.owner.released\n"
        "DispatchOwner.__slots__\n"
    )
    assert _private_reach_violations(ast.parse(legitimate), label) == []


def test_startup_exposes_no_migration_script_override(repository_root: Path) -> None:
    """Plan section 4.4 and Task 2 GREEN 9: maintenance migrates only through the
    packaged script directory; no parameter, keyword, attribute or name of the
    startup coordinator carries a script location."""
    label = _STARTUP_MODULE
    tree = _parse(_source_path(repository_root, label))
    assert _script_override_violations(tree, label) == []
    planted = (
        "apply_migrations(database, script_location=Path('elsewhere'))\n",
        "def maintain(path, *, script_location=None):\n    return path\n",
        "config.script_location = location\n",
        "script_location = Path('elsewhere')\n",
        "expected_head(script_location=location)\n",
    )
    for source in planted:
        assert _script_override_violations(ast.parse(source), label) != [], source
    legitimate = "applied = apply_migrations(database)\nhead = expected_head()\n"
    assert _script_override_violations(ast.parse(legitimate), label) == []
