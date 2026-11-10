"""Closed-world guards of the ``offline_data`` sub-project (plan section 2.6).

Two guard families live here. The source guards pin the Task 1, Task 2 and
Task 3 package census, the import roots the package may use, the absence of
environment, network and process reach, import-time purity and the no-write
rule. Two modules carry narrowly scoped allowances, each pinned to a named
function and an exact call shape, and every other module is held to the
reader's rule: ``normalize.py``, whose one admitted write is the exclusive
create of the container destination inside ``write_normalized_container`` and
whose one admitted removal is of the partial file that create produced, on the
same path, when the write fails (the plan's Task 2 file map admits this file
for the exclusive-create pin; the removal pin follows the Task 2 interface);
and ``cli.py``, for which the plan's Task 3 file map extends the no-write
guard family by pinning rather than exempting: the command may create
``--output`` with one directory-creation call, write only through one
exclusive-create helper and remove only files it created through one removal
helper, so it is admitted exactly one ``<path>.mkdir()`` inside
``_prepare_output_directory``, one ``<path>.open("xb")`` with one ``.write``
inside ``_write_new_file`` and one ``<path>.unlink()`` inside
``_remove_created``, each admitted by an AST scanner pinned to the named
function and the exact call shape, with disallowed-shape and admitted-shape
controls, and no other write is admitted. The entry-point module
``__main__.py`` holds exactly one guarded
``raise SystemExit(normalize_command(...))`` carrying the production providers
and is exempt from the import-time rule only inside that one
``if __name__ == "__main__":`` block. The runtime proofs show that reading a
fixture changes neither its bytes nor any directory, that writing a container
creates exactly the caller's destination and nothing else, and the four Task 3
command cases: a successful run creates exactly its output directory and three
files and nothing else; a run refused before its first write creates nothing
anywhere; a later failure whose removals all succeed leaves only the empty
directory the command created, every created file removed in reverse order;
and when a removal itself fails the only remnants beside that directory are
the created files whose removal failed, every removal still attempted in
reverse order, the outcome in flight standing and pre-existing entries
untouched (the directory is never removed).
The dependency guards pin the runtime dependency, the dev group, the constraint
set and the build requirement to plan section 2.7, every version recorded in
``uv.lock`` to the same list, the lock's ``directory = "../"`` record of the core
and the absence of every prohibited dependency family. They sit on one class,
``TestDependencyPins``, so one launcher selector,
``tests/safety/test_boundaries.py::TestDependencyPins``, runs exactly them: the
operator's negative control (a temporary protected-file mutation while the worker
is idle, then exact-byte restoration) proves they are load-bearing. Every scanner
carries synthetic self-tests, because a guard that is green from birth proves
nothing until it is shown to fail on the shapes it denies.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import json
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

import pytest

PACKAGE = "crypto_lab_offline_data"
EXPECTED_MODULES = (
    "__init__.py",
    "__main__.py",
    "binance_kline_csv.py",
    "candle_csv.py",
    "cli.py",
    "diagnostics.py",
    "metadata.py",
    "normalize.py",
    "providers.py",
    "validation.py",
)
ALLOWED_IMPORT_ROOTS = {
    PACKAGE,
    "__future__",
    "argparse",
    "collections",
    "crypto_lab",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "hashlib",
    "pathlib",
    "re",
    "typing",
    "uuid",
}
FORBIDDEN_IMPORT_ROOTS = {
    "asyncio",
    "ctypes",
    "ftplib",
    "http",
    "importlib",
    "multiprocessing",
    "os",
    "shutil",
    "smtplib",
    "socket",
    "ssl",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "urllib",
    "xmlrpc",
}
PROHIBITED_OS_ATTRIBUTES = {"environ", "getenv", "putenv", "unsetenv"}
PROHIBITED_CONTROL_LITERAL = "PYDANTIC_DISABLE_PLUGINS"
IMPORT_TIME_CALLS = {"dataclasses.dataclass", "re.compile"}
#: Write-shaped call names. ``FileType`` is argparse's file factory: once
#: ``argparse`` is an admitted root, ``argparse.FileType("w")(path)`` would
#: create or truncate a file without any ``open`` in the module, so the factory
#: itself is a write-shaped call wherever it appears (a ``type=`` argument
#: included). ``writelines`` is the sibling of ``write`` on a handle.
WRITE_ATTRIBUTES = {
    "FileType",
    "chmod",
    "copy",
    "copy2",
    "copyfile",
    "copytree",
    "hardlink_to",
    "link",
    "makedirs",
    "mkdir",
    "move",
    "remove",
    "removedirs",
    "rename",
    "renames",
    "replace",
    "rmdir",
    "rmtree",
    "symlink",
    "symlink_to",
    "touch",
    "truncate",
    "unlink",
    "write",
    "write_bytes",
    "write_text",
    "writelines",
}
READ_ONLY_OPEN_MODE = "rb"
#: The one module that may write, the one function in it that may, the one
#: open mode it may use (exclusive create, reached only after the writer has
#: inspected the destination's own entry without following it, so an existing
#: entry, a dangling reparse point included, is refused before the create
#: could follow it) and the one removal it may make: of the partial file that
#: create produced, on the same receiver, when the write fails.
WRITER_MODULE = "normalize.py"
WRITER_FUNCTION = "write_normalized_container"
WRITER_OPEN_MODE = "xb"
WRITER_REMOVAL = "unlink"
#: The command module and the three helpers that hold its admitted writes: one
#: ``<path>.mkdir()`` (no argument, no keyword, so no parent is created and no
#: existing entry is accepted) creating the output directory immediately
#: before the first write, one ``<path>.open("xb")`` with one ``.write``
#: creating each JSON file exclusively, and one ``<path>.unlink()`` removing,
#: in reverse order, the files the command created when a later step fails.
COMMAND_MODULE = "cli.py"
COMMAND_DIRECTORY_FUNCTION = "_prepare_output_directory"
COMMAND_WRITE_FUNCTION = "_write_new_file"
COMMAND_REMOVAL_FUNCTION = "_remove_created"
COMMAND_DIRECTORY_CALL = "mkdir"
#: The entry-point module: its one ``if __name__ == "__main__":`` block, whose
#: body is exactly ``raise SystemExit(normalize_command(...))``, is the only
#: import-time call site the module may hold.
ENTRY_POINT_MODULE = "__main__.py"
ENTRY_POINT_COMMAND = "normalize_command"

EXPECTED_RUNTIME_DEPENDENCIES = ["crypto-trading-lab"]
EXPECTED_SOURCES = {"crypto-trading-lab": {"path": "../", "editable": False}}
EXPECTED_REQUIRES_PYTHON = ">=3.12,<3.13"
EXPECTED_BUILD_REQUIRES = ["hatchling==1.31.0"]
EXPECTED_DEV_GROUP = [
    "colorama==0.4.6",
    "coverage==7.15.4",
    "hatchling==1.31.0",
    "iniconfig==2.3.0",
    "librt==0.15.0",
    "mypy==1.20.2",
    "mypy-extensions==1.1.0",
    "packaging==26.3",
    "pathspec==1.1.1",
    "pluggy==1.6.0",
    "pygments==2.20.0",
    "pytest==8.4.2",
    "pytest-cov==6.3.0",
    "ruff==0.16.2",
    "trove-classifiers==2026.6.1.19",
]
EXPECTED_CONSTRAINTS = [
    "alembic==1.20.0",
    "annotated-types==0.8.0",
    "greenlet==3.5.6",
    "mako==1.4.1",
    "markupsafe==3.0.3",
    "pydantic==2.13.4",
    "pydantic-core==2.46.4",
    "pyyaml==6.0.3",
    "sqlalchemy==2.0.54",
    "typing-extensions==4.16.0",
    "typing-inspection==0.4.4",
]
EXPECTED_LOCKED_VERSIONS = {
    "alembic": "1.20.0",
    "annotated-types": "0.8.0",
    "colorama": "0.4.6",
    "coverage": "7.15.4",
    "crypto-lab-offline-data": "0.1.0",
    "crypto-trading-lab": "0.1.0",
    "greenlet": "3.5.6",
    "hatchling": "1.31.0",
    "iniconfig": "2.3.0",
    "librt": "0.15.0",
    "mako": "1.4.1",
    "markupsafe": "3.0.3",
    "mypy": "1.20.2",
    "mypy-extensions": "1.1.0",
    "packaging": "26.3",
    "pathspec": "1.1.1",
    "pluggy": "1.6.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "pygments": "2.20.0",
    "pytest": "8.4.2",
    "pytest-cov": "6.3.0",
    "pyyaml": "6.0.3",
    "ruff": "0.16.2",
    "sqlalchemy": "2.0.54",
    "trove-classifiers": "2026.6.1.19",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.4",
}
EXPECTED_LOCK_REQUIRES_PYTHON = "==3.12.*"
EXPECTED_CORE_RUNTIME_NAMES = {"alembic", "pydantic", "pyyaml", "sqlalchemy"}
LOCAL_PACKAGES = {"crypto-lab-offline-data", "crypto-trading-lab"}
PYPI_REGISTRY = "https://pypi.org/simple"
EXPECTED_ADDOPTS = [
    "--strict-config",
    "--strict-markers",
    "--cov=crypto_lab_offline_data",
    "--cov-branch",
    "--cov-report=term-missing",
    "--cov-fail-under=98.61",
]
EXPECTED_COVERAGE_REPORT = {
    "fail_under": 98.61,
    "precision": 2,
    "show_missing": True,
    "skip_covered": True,
}
EXPECTED_COVERAGE_RUN = {"branch": True, "source": [PACKAGE]}
#: The core's ``tests/safety/test_project_dependencies.py`` families, verbatim.
PROHIBITED_FAMILIES = (
    "vectorbt",
    "freqtrade",
    "nautilus-trader",
    "jesse",
    "octobot",
    "hummingbot",
    "lean",
    "quantconnect",
    "binance",
    "ccxt",
    "alpaca",
    "ib-insync",
    "zerodha",
    "kiteconnect",
    "upstox",
    "openalgo",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "pyarrow",
    "pandas",
    "polars",
    "numpy",
    "ollama",
    "openai",
)
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _package_dir(sub_project_root: Path) -> Path:
    return sub_project_root / "src" / PACKAGE


def _expected_module_paths(sub_project_root: Path) -> tuple[Path, ...]:
    """The census modules by name, so a missing module fails every scan."""
    package = _package_dir(sub_project_root)
    return tuple(package / name for name in EXPECTED_MODULES)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


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


def _resolved_qualified_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    name = _qualified_name(node)
    if name is None:
        return None
    head, separator, tail = name.partition(".")
    resolved = aliases.get(head, head)
    return resolved if not separator else f"{resolved}.{tail}"


def _imported_roots(tree: ast.AST) -> tuple[str, ...]:
    roots: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.append(node.module.partition(".")[0])
    return tuple(roots)


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


def _environment_access_violations(tree: ast.AST, relative_path: str) -> list[str]:
    violations: list[str] = []
    os_aliases = _os_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name in PROHIBITED_OS_ATTRIBUTES:
                    violations.append(
                        f"{relative_path}:{node.lineno}: "
                        f"prohibited from os import {alias.name}"
                    )
        if isinstance(node, ast.Attribute) and node.attr in PROHIBITED_OS_ATTRIBUTES:
            base = _qualified_name(node.value)
            if base in os_aliases:
                violations.append(
                    f"{relative_path}:{node.lineno}: prohibited os.{node.attr}"
                )
        if isinstance(node, ast.Call) and _qualified_name(node.func) == "getattr":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                attr = node.args[1].value
                if isinstance(attr, str) and attr in PROHIBITED_OS_ATTRIBUTES:
                    base = _qualified_name(node.args[0])
                    if base in os_aliases:
                        violations.append(
                            f"{relative_path}:{node.lineno}: "
                            f"prohibited getattr os access {attr}"
                        )
        if isinstance(node, ast.Constant) and node.value == PROHIBITED_CONTROL_LITERAL:
            violations.append(
                f"{relative_path}:{node.lineno}: prohibited control literal"
            )
    return violations


def _import_time_nodes(body: list[ast.stmt]) -> Iterator[ast.AST]:
    """Yield every node Python evaluates when the module is imported.

    Function bodies run only when called, so a function contributes its
    decorators and argument defaults; a class body runs at import, so it is
    walked with the same rule; every other statement is yielded whole.
    """
    for statement in body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            yield from statement.decorator_list
            yield from statement.args.defaults
            for default in statement.args.kw_defaults:
                if default is not None:
                    yield default
        elif isinstance(statement, ast.ClassDef):
            yield from statement.decorator_list
            yield from statement.bases
            yield from (keyword.value for keyword in statement.keywords)
            yield from _import_time_nodes(statement.body)
        else:
            yield statement


def _import_time_call_violations(tree: ast.Module, relative_path: str) -> list[str]:
    aliases = _import_aliases(tree)
    violations: list[str] = []
    for node in _import_time_nodes(tree.body):
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = _resolved_qualified_name(call.func, aliases)
            if name not in IMPORT_TIME_CALLS:
                violations.append(
                    f"{relative_path}:{call.lineno}: import-time call {name}"
                )
    return violations


def _callee(node: ast.Call, aliases: dict[str, str]) -> str | None:
    """The name a call targets.

    The attribute of a method call, else the last segment of the callee
    resolved through the module's imports, so ``FT("w")`` after
    ``from argparse import FileType as FT`` is seen as ``FileType``.
    """
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    resolved = _resolved_qualified_name(node.func, aliases)
    return None if resolved is None else resolved.rpartition(".")[2]


def _receiver(node: ast.Call) -> str | None:
    """The receiver of a method call, else ``None``."""
    if isinstance(node.func, ast.Attribute):
        return _qualified_name(node.func.value)
    return None


def _write_shaped_reference_violations(
    tree: ast.AST, relative_path: str, admitted: set[int]
) -> list[str]:
    """References to write-shaped names outside the admitted call positions.

    The call scanners match the name a call targets; these rules close the
    aliasing routes around them: a ``from`` import of a write-shaped name
    (whatever it is bound to), an attribute reference to one that is not the
    target of an admitted call (``factory = argparse.FileType``,
    ``remove = path.unlink``) and ``getattr(..., "<name>")``. ``open`` joins
    the import and ``getattr`` rules so the open-mode checks cannot be bypassed
    that way, but not the attribute rule: a candle row's ``open`` price is an
    attribute of the same name, so a bound ``.open`` reference is flagged only
    where it is assigned to a name (``opener = path.open``).
    """
    names = WRITE_ATTRIBUTES | {"open"}
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in names:
                    violations.append(
                        f"{relative_path}:{node.lineno}: imports the write-shaped "
                        f"name {alias.name}"
                    )
        elif isinstance(node, ast.Attribute):
            if node.attr in WRITE_ATTRIBUTES and id(node) not in admitted:
                violations.append(
                    f"{relative_path}:{node.lineno}: write-shaped reference {node.attr}"
                )
        elif isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "open":
                violations.append(
                    f"{relative_path}:{node.lineno}: binds a bound open reference"
                )
        elif isinstance(node, ast.Call) and _qualified_name(node.func) == "getattr":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                attribute = node.args[1].value
                if isinstance(attribute, str) and attribute in names:
                    violations.append(
                        f"{relative_path}:{node.lineno}: getattr write-shaped "
                        f"access {attribute}"
                    )
    return violations


def _write_call_violations(tree: ast.AST, relative_path: str) -> list[str]:
    aliases = _import_aliases(tree)
    admitted: set[int] = set()
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _callee(node, aliases)
        if callee in WRITE_ATTRIBUTES:
            violations.append(f"{relative_path}:{node.lineno}: write call {callee}")
        if callee == "open":
            modes = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
            exact = len(node.args) == 1 and modes == [READ_ONLY_OPEN_MODE]
            if exact and not node.keywords:
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: open is not exactly open('rb')"
                )
    violations.extend(_write_shaped_reference_violations(tree, relative_path, admitted))
    return violations


def _function_span(tree: ast.Module, name: str) -> range | None:
    """The line span of the one top-level function ``name``, else ``None``."""
    definitions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(definitions) != 1 or definitions[0].end_lineno is None:
        return None
    return range(definitions[0].lineno, definitions[0].end_lineno + 1)


def _writer_function_span(tree: ast.Module) -> range | None:
    """The line span of the one top-level ``WRITER_FUNCTION``, else ``None``."""
    return _function_span(tree, WRITER_FUNCTION)


def _writer_module_violations(tree: ast.Module, relative_path: str) -> list[str]:
    """Write calls the writer module may not make.

    Outside ``WRITER_FUNCTION`` the module is held to the same rule as every
    other module. Inside it exactly one ``<path>.open("xb")`` (the ``Path``
    method, one positional argument, no keyword), exactly one ``.write`` call
    and exactly one ``<path>.unlink()`` on the receiver of that open (no
    argument, no keyword: the removal of the partial file the exclusive create
    produced, when the write fails) are admitted; a different mode, the
    built-in ``open``, a second open, write or removal, a removal of another
    receiver, with an argument or with ``missing_ok``, or any other
    write-shaped call is a violation.
    """
    span = _writer_function_span(tree)
    if span is None:
        return [f"{relative_path}: {WRITER_FUNCTION} must be defined exactly once"]
    aliases = _import_aliases(tree)
    admitted: set[int] = set()
    violations: list[str] = []
    writes = 0
    opened: list[str | None] = []
    removed: list[str | None] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _callee(node, aliases)
        receiver = _receiver(node)
        inside = node.lineno in span
        if callee == "open":
            modes = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
            exact = (
                isinstance(node.func, ast.Attribute)
                and len(node.args) == 1
                and modes == [WRITER_OPEN_MODE]
                and not node.keywords
            )
            if inside and exact:
                opened.append(receiver)
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: "
                    f"open is not the writer's exclusive open('{WRITER_OPEN_MODE}')"
                )
        elif callee == "write":
            if inside:
                writes += 1
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: write outside {WRITER_FUNCTION}"
                )
        elif callee == WRITER_REMOVAL:
            exact = (
                isinstance(node.func, ast.Attribute)
                and not node.args
                and not node.keywords
            )
            if inside and exact:
                removed.append(receiver)
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: {WRITER_REMOVAL} is not the "
                    f"writer's removal of its own partial file"
                )
        elif callee in WRITE_ATTRIBUTES:
            violations.append(f"{relative_path}:{node.lineno}: write call {callee}")
    violations.extend(_write_shaped_reference_violations(tree, relative_path, admitted))
    if len(opened) != 1:
        violations.append(
            f"{relative_path}: {WRITER_FUNCTION} must open its destination "
            f"exactly once, found {len(opened)}"
        )
    if writes != 1:
        violations.append(
            f"{relative_path}: {WRITER_FUNCTION} must write exactly once, "
            f"found {writes}"
        )
    if len(removed) != 1:
        violations.append(
            f"{relative_path}: {WRITER_FUNCTION} must remove its partial file "
            f"exactly once, found {len(removed)}"
        )
    elif removed[0] is None or removed != opened:
        violations.append(
            f"{relative_path}: {WRITER_FUNCTION} must remove only the destination "
            f"it opened"
        )
    return violations


def _command_module_violations(tree: ast.Module, relative_path: str) -> list[str]:
    """Write calls the command module may not make.

    Outside the three named helpers the module is held to the reader's
    no-write rule. Inside them exactly one ``<path>.mkdir()`` (the ``Path``
    method, no argument, no keyword) in ``COMMAND_DIRECTORY_FUNCTION``, exactly
    one ``<path>.open("xb")`` (one positional argument, no keyword) with exactly
    one ``.write`` call in ``COMMAND_WRITE_FUNCTION``, and exactly one
    ``<path>.unlink()`` (no argument, no keyword) in ``COMMAND_REMOVAL_FUNCTION``
    are admitted; a different mode, the built-in ``open``, a second call of any
    of them, a call outside its helper, an argument or keyword on the directory
    or removal call, or any other write-shaped call is a violation.
    """
    spans = {
        name: _function_span(tree, name)
        for name in (
            COMMAND_DIRECTORY_FUNCTION,
            COMMAND_WRITE_FUNCTION,
            COMMAND_REMOVAL_FUNCTION,
        )
    }
    violations = [
        f"{relative_path}: {name} must be defined exactly once"
        for name, span in spans.items()
        if span is None
    ]
    if violations:
        return violations
    directory_span = spans[COMMAND_DIRECTORY_FUNCTION] or range(0)
    write_span = spans[COMMAND_WRITE_FUNCTION] or range(0)
    removal_span = spans[COMMAND_REMOVAL_FUNCTION] or range(0)
    aliases = _import_aliases(tree)
    admitted: set[int] = set()
    created_directories = 0
    opened = 0
    writes = 0
    removed = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _callee(node, aliases)
        is_method = isinstance(node.func, ast.Attribute)
        bare = is_method and not node.args and not node.keywords
        if callee == COMMAND_DIRECTORY_CALL:
            if node.lineno in directory_span and bare:
                created_directories += 1
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: {callee} is not the command's "
                    f"creation of its output directory"
                )
        elif callee == "open":
            modes = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
            exact = (
                is_method
                and len(node.args) == 1
                and modes == [WRITER_OPEN_MODE]
                and not node.keywords
            )
            if node.lineno in write_span and exact:
                opened += 1
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: "
                    f"open is not the command's exclusive open('{WRITER_OPEN_MODE}')"
                )
        elif callee == "write":
            if node.lineno in write_span:
                writes += 1
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: write outside "
                    f"{COMMAND_WRITE_FUNCTION}"
                )
        elif callee == WRITER_REMOVAL:
            if node.lineno in removal_span and bare:
                removed += 1
                admitted.add(id(node.func))
            else:
                violations.append(
                    f"{relative_path}:{node.lineno}: {WRITER_REMOVAL} is not the "
                    f"command's reverse-order removal of a file it created"
                )
        elif callee in WRITE_ATTRIBUTES:
            violations.append(f"{relative_path}:{node.lineno}: write call {callee}")
    violations.extend(_write_shaped_reference_violations(tree, relative_path, admitted))
    for count, call, where in (
        (created_directories, COMMAND_DIRECTORY_CALL, COMMAND_DIRECTORY_FUNCTION),
        (opened, "open", COMMAND_WRITE_FUNCTION),
        (writes, "write", COMMAND_WRITE_FUNCTION),
        (removed, WRITER_REMOVAL, COMMAND_REMOVAL_FUNCTION),
    ):
        if count != 1:
            violations.append(
                f"{relative_path}: {where} must call {call} exactly once, found {count}"
            )
    return violations


def _is_main_guard(test: ast.expr) -> bool:
    """Whether ``test`` is exactly ``__name__ == "__main__"``."""
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _is_entry_raise(statement: ast.stmt) -> bool:
    """Whether ``statement`` is ``raise SystemExit(normalize_command(...))``."""
    if not isinstance(statement, ast.Raise) or statement.cause is not None:
        return False
    exc = statement.exc
    if (
        not isinstance(exc, ast.Call)
        or _qualified_name(exc.func) != "SystemExit"
        or len(exc.args) != 1
        or exc.keywords
    ):
        return False
    inner = exc.args[0]
    return (
        isinstance(inner, ast.Call)
        and _qualified_name(inner.func) == ENTRY_POINT_COMMAND
    )


def _entry_point_violations(tree: ast.Module, relative_path: str) -> list[str]:
    """Import-time calls the entry-point module may not make.

    The module body is imports plus exactly one ``if __name__ == "__main__":``
    block without ``else`` whose body is exactly one
    ``raise SystemExit(normalize_command(...))``; that block is the only
    admitted import-time call site. Every other statement is held to the
    import-time rule of every module.
    """
    guards = [statement for statement in tree.body if isinstance(statement, ast.If)]
    rest = [statement for statement in tree.body if not isinstance(statement, ast.If)]
    violations = _import_time_call_violations(
        ast.Module(body=rest, type_ignores=[]), relative_path
    )
    if len(guards) != 1:
        violations.append(
            f"{relative_path}: exactly one entry-point guard is admitted, "
            f"found {len(guards)}"
        )
        return violations
    guard = guards[0]
    if not _is_main_guard(guard.test) or guard.orelse:
        violations.append(
            f"{relative_path}:{guard.lineno}: the guard is not the __main__ guard"
        )
    if len(guard.body) != 1 or not _is_entry_raise(guard.body[0]):
        violations.append(
            f"{relative_path}:{guard.lineno}: the guard body is not exactly "
            f"raise SystemExit({ENTRY_POINT_COMMAND}(...))"
        )
    return violations


def _snapshot(directory: Path) -> tuple[tuple[str, int], ...]:
    """Names and sizes of a directory's entries; directories carry size -1."""
    entries: list[tuple[str, int]] = []
    for entry in sorted(directory.iterdir()):
        size = entry.stat().st_size if entry.is_file() else -1
        entries.append((entry.name, size))
    return tuple(entries)


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _normalized_requirement_name(requirement: str) -> str:
    match = _REQUIREMENT_NAME.match(requirement)
    assert match is not None, f"Cannot parse dependency name from {requirement!r}"
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def _is_prohibited(requirement: str) -> bool:
    name = _normalized_requirement_name(requirement)
    return any(family in name for family in PROHIBITED_FAMILIES)


def _pinned_name_and_specifier(requirement: str) -> dict[str, str]:
    name, separator, version = requirement.partition("==")
    assert separator == "==", requirement
    return {"name": name, "specifier": f"=={version}"}


def test_the_package_census_is_exactly_the_task_one_two_and_three_modules(
    sub_project_root: Path,
) -> None:
    """The slice's nine modules, and nothing else, form the package."""
    package = _package_dir(sub_project_root)

    names = tuple(sorted(path.name for path in package.glob("*.py")))
    subpackages = [
        entry.name
        for entry in package.iterdir()
        if entry.is_dir() and entry.name != "__pycache__"
    ]

    assert names == EXPECTED_MODULES
    assert subpackages == []


def test_every_module_imports_only_the_allowlisted_roots(
    sub_project_root: Path,
) -> None:
    failures: list[str] = []
    for path in _expected_module_paths(sub_project_root):
        for root in _imported_roots(_parse(path)):
            if root not in ALLOWED_IMPORT_ROOTS:
                failures.append(f"{path.name}: {root}")

    assert failures == []
    assert ALLOWED_IMPORT_ROOTS.isdisjoint(FORBIDDEN_IMPORT_ROOTS)


def test_no_module_reads_the_environment_or_names_the_pydantic_control(
    sub_project_root: Path,
) -> None:
    failures: list[str] = []
    for path in _expected_module_paths(sub_project_root):
        failures.extend(_environment_access_violations(_parse(path), path.name))

    assert failures == []


def test_importing_every_module_performs_no_side_effect(
    sub_project_root: Path,
) -> None:
    """Import time may compile patterns and declare dataclasses, nothing else.

    The entry-point module is held to the same rule outside its one guarded
    block, which the next test pins to its exact shape.
    """
    failures: list[str] = []
    for path in _expected_module_paths(sub_project_root):
        if path.name == ENTRY_POINT_MODULE:
            continue
        failures.extend(_import_time_call_violations(_parse(path), path.name))

    assert failures == []
    assert ENTRY_POINT_MODULE in EXPECTED_MODULES


def test_the_entry_point_module_holds_exactly_one_guarded_command_call(
    sub_project_root: Path,
) -> None:
    """``__main__.py`` holds imports and one guarded ``raise SystemExit(...)``.

    The guard body's arguments are not shaped here; the module stays under the
    import-root, environment and no-write scans like every other module, so a
    write-shaped argument (``argparse.FileType`` included) is caught there.
    """
    path = _package_dir(sub_project_root) / ENTRY_POINT_MODULE

    assert _entry_point_violations(_parse(path), path.name) == []
    assert _write_call_violations(_parse(path), path.name) == []


def test_no_module_but_the_writer_and_the_command_contains_a_write_call(
    sub_project_root: Path,
) -> None:
    """Every module but ``normalize.py`` and ``cli.py`` keeps the no-write rule."""
    failures: list[str] = []
    for path in _expected_module_paths(sub_project_root):
        if path.name in {WRITER_MODULE, COMMAND_MODULE}:
            continue
        failures.extend(_write_call_violations(_parse(path), path.name))

    assert failures == []
    assert WRITER_MODULE in EXPECTED_MODULES
    assert COMMAND_MODULE in EXPECTED_MODULES
    assert WRITER_MODULE != COMMAND_MODULE


def test_the_writer_module_writes_only_through_the_exclusive_create_in_the_writer(
    sub_project_root: Path,
) -> None:
    """``normalize.py`` opens once with ``"xb"``, writes once, removes once."""
    path = _package_dir(sub_project_root) / WRITER_MODULE

    assert _writer_module_violations(_parse(path), path.name) == []


def test_the_command_module_writes_only_through_its_three_named_helpers(
    sub_project_root: Path,
) -> None:
    """``cli.py``: one ``mkdir()``, one ``open("xb")`` and write, one ``unlink()``."""
    path = _package_dir(sub_project_root) / COMMAND_MODULE

    assert _command_module_violations(_parse(path), path.name) == []


def test_reading_a_fixture_leaves_input_and_directories_unchanged(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: Any,
    fixed_clock: Any,
) -> None:
    """The reader writes nothing: not to its input, its directory or the cwd."""
    from crypto_lab.domain.results import Success

    from crypto_lab_offline_data.candle_csv import read_ohlcv_csv

    copied = tmp_path / "input.csv"
    copied.write_bytes(clean_fixture.read_bytes())
    fixture_digest = hashlib.sha256(clean_fixture.read_bytes()).hexdigest()
    copied_digest = hashlib.sha256(copied.read_bytes()).hexdigest()
    working_directory = Path.cwd()
    before = (
        _snapshot(tmp_path),
        _snapshot(clean_fixture.parent),
        _snapshot(working_directory),
    )

    results = (
        read_ohlcv_csv(copied, ids=fixed_ids, clock=fixed_clock),
        read_ohlcv_csv(clean_fixture, ids=fixed_ids, clock=fixed_clock),
    )

    assert all(isinstance(result, Success) for result in results)
    assert hashlib.sha256(clean_fixture.read_bytes()).hexdigest() == fixture_digest
    assert hashlib.sha256(copied.read_bytes()).hexdigest() == copied_digest
    assert (
        _snapshot(tmp_path),
        _snapshot(clean_fixture.parent),
        _snapshot(working_directory),
    ) == before
    assert Path.cwd() == working_directory


def test_writing_a_container_creates_exactly_the_destination_and_nothing_else(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: Any,
    fixed_clock: Any,
) -> None:
    """The writer touches one path: the caller's destination, created exclusively."""
    from crypto_lab.domain.results import Success

    from crypto_lab_offline_data.candle_csv import read_ohlcv_csv
    from crypto_lab_offline_data.normalize import write_normalized_container
    from crypto_lab_offline_data.validation import validate_series

    read = read_ohlcv_csv(clean_fixture, ids=fixed_ids, clock=fixed_clock)
    assert isinstance(read, Success)
    validated = validate_series(
        read.value, timeframe="1m", ids=fixed_ids, clock=fixed_clock
    )
    assert isinstance(validated, Success)
    destination = tmp_path / "part-0000.ndjson"
    fixture_digest = hashlib.sha256(clean_fixture.read_bytes()).hexdigest()
    working_directory = Path.cwd()
    before = (
        _snapshot(tmp_path),
        _snapshot(clean_fixture.parent),
        _snapshot(working_directory),
    )
    assert before[0] == ()

    result = write_normalized_container(
        validated.value, destination, ids=fixed_ids, clock=fixed_clock
    )

    assert isinstance(result, Success)
    container = result.value
    assert _snapshot(tmp_path) == (("part-0000.ndjson", container.bytes_written),)
    assert _snapshot(clean_fixture.parent) == before[1]
    assert _snapshot(working_directory) == before[2]
    assert hashlib.sha256(clean_fixture.read_bytes()).hexdigest() == fixture_digest
    assert Path.cwd() == working_directory
    assert destination.read_bytes().count(b"\n") == container.row_count


def _command_argv(input_path: Path, output: Path) -> list[str]:
    return [
        "normalize",
        "--input",
        str(input_path),
        "--output",
        str(output),
        "--instrument",
        "BINANCE:BTC/USDT:SPOT",
        "--timeframe",
        "1m",
    ]


def test_the_command_creates_exactly_its_output_directory_and_three_files(
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: Any,
    fixed_clock: Any,
) -> None:
    """Run-time confinement: the output directory and its three files, nothing else."""
    from crypto_lab_offline_data.cli import OUTPUT_FILE_NAMES, normalize_command

    output = tmp_path / "output"
    fixture_digest = hashlib.sha256(clean_fixture.read_bytes()).hexdigest()
    working_directory = Path.cwd()
    before = (
        _snapshot(tmp_path),
        _snapshot(clean_fixture.parent),
        _snapshot(working_directory),
    )
    assert before[0] == ()

    code = normalize_command(
        _command_argv(clean_fixture, output), ids=fixed_ids, clock=fixed_clock
    )

    assert code == 0
    assert _snapshot(tmp_path) == (("output", -1),)
    assert tuple(name for name, _ in _snapshot(output)) == tuple(
        sorted(OUTPUT_FILE_NAMES)
    )
    assert all(size > 0 for _, size in _snapshot(output))
    assert _snapshot(clean_fixture.parent) == before[1]
    assert _snapshot(working_directory) == before[2]
    assert hashlib.sha256(clean_fixture.read_bytes()).hexdigest() == fixture_digest
    assert Path.cwd() == working_directory


def test_a_refused_command_run_creates_nothing_anywhere(
    tmp_path: Path,
    invalid_root: Path,
    fixed_ids: Any,
    fixed_clock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A refusal before the first write leaves every directory as it was."""
    from crypto_lab_offline_data.cli import normalize_command

    refused_input = invalid_root / "header-only.csv"
    output = tmp_path / "output"
    working_directory = Path.cwd()
    before = (
        _snapshot(tmp_path),
        _snapshot(invalid_root),
        _snapshot(working_directory),
    )

    code = normalize_command(
        _command_argv(refused_input, output), ids=fixed_ids, clock=fixed_clock
    )

    assert code == 1
    assert not output.exists()
    assert (
        _snapshot(tmp_path),
        _snapshot(invalid_root),
        _snapshot(working_directory),
    ) == before
    assert Path.cwd() == working_directory
    assert str(refused_input) not in capsys.readouterr().out


#: The failure-injection doubles of ``tests/unit/test_cli.py``, restated here
#: because the test tree is not a package: a handle over a real exclusively
#: created file whose write fails after a prefix, and a ``Path.unlink`` recorder
#: that denies the removals named to it so the remnants can be told apart.
PARTIAL_PREFIX_LENGTH = 16
SIBLING_NAME = "sibling.txt"
SIBLING_BYTES = b"pre-existing sibling\n"
SIBLING_ENTRY = (SIBLING_NAME, len(SIBLING_BYTES))


class _FailingHandle:
    """A handle over a real exclusively created file that fails after a prefix."""

    def __init__(self, inner: IO[bytes], path: Path, observed: list[str]) -> None:
        self._inner = inner
        self._path = path
        self._observed = observed

    def __enter__(self) -> _FailingHandle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._inner.close()

    def write(self, data: bytes) -> int:
        self._inner.write(data[:PARTIAL_PREFIX_LENGTH])
        self._inner.flush()
        self._observed.append(self._path.name)
        raise OSError(errno.ENOSPC, "injected write failure")


def _fail_the_write_of(patch: pytest.MonkeyPatch, name: str) -> list[str]:
    """Make the exclusive create of ``name`` succeed and its write fail mid-way."""
    observed: list[str] = []
    real_open = Path.open

    def failing_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if mode == "xb" and self.name == name:
            return _FailingHandle(real_open(self, "xb"), self, observed)
        return real_open(self, mode, *args, **kwargs)

    patch.setattr(Path, "open", failing_open)
    return observed


def _record_unlinks(
    patch: pytest.MonkeyPatch, *, failing: frozenset[str]
) -> list[Path]:
    """Record every ``Path.unlink`` in call order; a name in ``failing`` is denied."""
    unlinked: list[Path] = []
    real_unlink = Path.unlink

    def recording_unlink(self: Path, missing_ok: bool = False) -> None:
        unlinked.append(self)
        if self.name in failing:
            raise PermissionError(errno.EACCES, "injected removal failure")
        real_unlink(self, missing_ok)

    patch.setattr(Path, "unlink", recording_unlink)
    return unlinked


def _plant_sibling(tmp_path: Path) -> Path:
    """A pre-existing entry beside the output directory, never the command's."""
    sibling = tmp_path / SIBLING_NAME
    sibling.write_bytes(SIBLING_BYTES)
    return sibling


def _assert_output_refusal_line(text: str, diagnostic_id: str) -> None:
    """The outcome in flight: one canonical-JSON ``OUTPUT_DIRECTORY`` refusal line."""
    from crypto_lab_offline_data.diagnostics import RefusalCode

    assert text.endswith("\n")
    assert text.count("\n") == 1
    printed = json.loads(text)
    assert printed["outcome"] == "FAILURE"
    assert len(printed["diagnostics"]) == 1
    diagnostic = printed["diagnostics"][0]
    assert diagnostic["error_code"] == RefusalCode.OUTPUT_DIRECTORY.value
    assert diagnostic["diagnostic_id"] == diagnostic_id
    assert diagnostic["details"] == {
        "line": 0,
        "rule": RefusalCode.OUTPUT_DIRECTORY.value,
        "value_length": 0,
    }


@pytest.mark.parametrize("failing_write", ["descriptor.json", "partitions.json"])
def test_a_later_failure_whose_removals_succeed_leaves_only_the_created_directory(
    failing_write: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: Any,
    fixed_clock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A JSON write fails after the command created ``--output``: full cleanup.

    The output directory starts absent, so the command creates it; every file
    it created is then removed, last first, and the directory it created is
    the one remnant, empty, beside the planted sibling, which is untouched.
    The ``OUTPUT_DIRECTORY`` refusal in flight stands.
    """
    from crypto_lab_offline_data.cli import OUTPUT_FILE_NAMES, normalize_command

    output = tmp_path / "output"
    sibling = _plant_sibling(tmp_path)
    working_directory = Path.cwd()
    before = (_snapshot(clean_fixture.parent), _snapshot(working_directory))
    assert not output.exists()
    assert _snapshot(tmp_path) == (SIBLING_ENTRY,)
    created_order = OUTPUT_FILE_NAMES[: OUTPUT_FILE_NAMES.index(failing_write) + 1]

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, failing_write)
        unlinked = _record_unlinks(patch, failing=frozenset())
        code = normalize_command(
            _command_argv(clean_fixture, output), ids=fixed_ids, clock=fixed_clock
        )

    assert code == 1
    _assert_output_refusal_line(capsys.readouterr().out, fixed_ids.diagnostic_id())
    assert observed == [failing_write]
    assert unlinked == [output / name for name in reversed(created_order)]
    assert len(unlinked) == len(created_order) >= 2
    assert output.is_dir()
    assert _snapshot(output) == ()
    assert _snapshot(tmp_path) == (("output", -1), SIBLING_ENTRY)
    assert sibling.read_bytes() == SIBLING_BYTES
    assert (_snapshot(clean_fixture.parent), _snapshot(working_directory)) == before
    assert Path.cwd() == working_directory


@pytest.mark.parametrize(
    "failing_removal",
    ["partitions.json", "descriptor.json"],
    ids=["first-attempted", "second-attempted"],
)
def test_a_failed_removal_leaves_only_the_created_files_whose_removal_failed(
    failing_removal: str,
    tmp_path: Path,
    clean_fixture: Path,
    fixed_ids: Any,
    fixed_clock: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One removal is denied: the others are still attempted, last first.

    The ``partitions.json`` write fails after a prefix, so the command created
    all three files and the directory; the removal of ``failing_removal`` is
    denied and every other removal is attempted and succeeds. The denied file,
    byte for byte what the command wrote, is the one remnant beside the
    directory, which is never removed; the planted sibling and a reference
    run's directory are untouched; the ``OUTPUT_DIRECTORY`` refusal stands.
    """
    from crypto_lab_offline_data.cli import OUTPUT_FILE_NAMES, normalize_command

    reference = tmp_path / "reference"
    reference_code = normalize_command(
        _command_argv(clean_fixture, reference), ids=fixed_ids, clock=fixed_clock
    )
    assert reference_code == 0
    reference_before = _snapshot(reference)
    reference_bytes = (reference / failing_removal).read_bytes()
    if failing_removal == "partitions.json":
        reference_bytes = reference_bytes[:PARTIAL_PREFIX_LENGTH]
    output = tmp_path / "output"
    sibling = _plant_sibling(tmp_path)
    working_directory = Path.cwd()
    before = (_snapshot(clean_fixture.parent), _snapshot(working_directory))
    assert not output.exists()

    with pytest.MonkeyPatch.context() as patch:
        observed = _fail_the_write_of(patch, "partitions.json")
        unlinked = _record_unlinks(patch, failing=frozenset({failing_removal}))
        code = normalize_command(
            _command_argv(clean_fixture, output), ids=fixed_ids, clock=fixed_clock
        )

    assert code == 1
    _assert_output_refusal_line(capsys.readouterr().out, fixed_ids.diagnostic_id())
    assert observed == ["partitions.json"]
    assert unlinked == [output / name for name in reversed(OUTPUT_FILE_NAMES)]
    assert unlinked.index(output / failing_removal) < len(unlinked) - 1
    assert output.is_dir()
    assert _snapshot(output) == ((failing_removal, len(reference_bytes)),)
    assert (output / failing_removal).read_bytes() == reference_bytes
    assert _snapshot(tmp_path) == (("output", -1), ("reference", -1), SIBLING_ENTRY)
    assert _snapshot(reference) == reference_before
    assert sibling.read_bytes() == SIBLING_BYTES
    assert (_snapshot(clean_fixture.parent), _snapshot(working_directory)) == before
    assert Path.cwd() == working_directory


@pytest.mark.parametrize(
    "source",
    [
        "import socket",
        "from urllib.request import urlopen",
        "import http.client",
        "import subprocess as run",
        "from os import environ",
        "import sys",
        "import json",
    ],
)
def test_the_import_root_scanner_detects_each_foreign_root(source: str) -> None:
    roots = set(_imported_roots(ast.parse(source)))

    assert not roots <= ALLOWED_IMPORT_ROOTS


@pytest.mark.parametrize(
    "source",
    [
        'import os\nVALUE = os.environ["HOME"]',
        'import os\nVALUE = os.getenv("HOME")',
        "from os import environ",
        'import os as system\nsystem.putenv("HOME", "x")',
        'import os\nVALUE = getattr(os, "unsetenv")',
        'CONTROL = "PYDANTIC_DISABLE_PLUGINS"',
    ],
)
def test_the_environment_scanner_detects_each_forbidden_shape(source: str) -> None:
    assert _environment_access_violations(ast.parse(source), "synthetic.py") != []


def test_the_environment_scanner_admits_plain_module_code() -> None:
    source = 'import re\nPATTERN = re.compile("x")\nVALUE = PATTERN.pattern'

    assert _environment_access_violations(ast.parse(source), "synthetic.py") == []


@pytest.mark.parametrize(
    "source",
    [
        'import pathlib\nTEXT = pathlib.Path("x").read_text()',
        'print("hello")',
        "VALUE = compute()",
        "class Config:\n    VALUE = load()",
        "def f(x=compute()):\n    return x",
        "def f(*, x=compute()):\n    return x",
        "@register()\ndef f():\n    return 1",
        "@register()\nclass Row:\n    line: int",
        "class Row(make_base()):\n    line: int",
        "import datetime\nNOW = datetime.datetime.now()",
        "from re import compile\nPATTERN = compile('x')\nVALUE = len(PATTERN.pattern)",
    ],
)
def test_the_import_time_scanner_detects_each_side_effect_shape(source: str) -> None:
    assert _import_time_call_violations(ast.parse(source), "synthetic.py") != []


@pytest.mark.parametrize(
    "source",
    [
        'import re\nPATTERN = re.compile("x")',
        "from re import compile\nPATTERN = compile('x')",
        "from dataclasses import dataclass as d\n@d(frozen=True)\nclass R:\n    a: int",
        "def f():\n    return compute()",
        "class Row:\n    def method(self):\n        return compute()",
        "class Row:\n    @property\n    def value(self):\n        return compute()",
        "LIMIT = 64 * 1024 * 1024",
        "type Alias = tuple[int, ...]",
    ],
)
def test_the_import_time_scanner_admits_each_pure_shape(source: str) -> None:
    assert _import_time_call_violations(ast.parse(source), "synthetic.py") == []


@pytest.mark.parametrize(
    "source",
    [
        'path.write_text("x")',
        'path.write_bytes(b"x")',
        'open(path, "w")',
        "open(path)",
        'path.open("w")',
        'path.open("rb", buffering=0)',
        'path.open(mode="rb")',
        "path.open()",
        'path.open("r")',
        "path.mkdir()",
        "path.unlink()",
        "path.rename(other)",
        "path.replace(other)",
        "path.touch()",
        "os.remove(path)",
        "shutil.rmtree(path)",
        'handle.write(b"x")',
        'handle.writelines([b"x"])',
        'argparse.FileType("w")(path)',
        'import argparse\nparser.add_argument("--out", type=argparse.FileType("w"))',
        'from argparse import FileType\nhandle = FileType("wb")(path)',
        'raise SystemExit(normalize_command(argparse.FileType("w")(path)))',
        'from argparse import FileType as FT\nhandle = FT("w")(path)',
        'import argparse\nfactory = argparse.FileType\nhandle = factory("w")(path)',
        'import argparse\nhandle = getattr(argparse, "FileType")("w")(path)',
        'import argparse as ap\nhandle = ap.FileType("w")(path)',
        "remove = path.unlink\nremove()",
        "from os import unlink as rm\nrm(path)",
        'getattr(path, "unlink")()',
        'opener = path.open\nopener("wb")',
        'getattr(path, "open")("wb")',
        'from io import open as opener\nopener(path, "w")',
    ],
)
def test_the_write_scanner_detects_each_write_shape(source: str) -> None:
    assert _write_call_violations(ast.parse(source), "synthetic.py") != []


@pytest.mark.parametrize(
    "source",
    [
        'with path.open("rb") as handle:\n    data = handle.read(1)',
        "data = path.read_bytes()",
        'text = data.decode("utf-8")',
        'text.removesuffix("x")',
        "fields = line.split(',')",
        "import argparse as ap\nparser = ap.ArgumentParser()",
        "from argparse import ArgumentParser\nparser = ArgumentParser()",
        "from pathlib import Path\nvalue = Path(name).name",
        "value = getattr(ids, method)()",
    ],
)
def test_the_write_scanner_admits_each_read_only_shape(source: str) -> None:
    assert _write_call_violations(ast.parse(source), "synthetic.py") == []


WRITER_SHAPE = (
    "def write_normalized_container(series, path):\n"
    "    try:\n"
    '        with path.open("xb") as handle:\n'
    "            handle.write(data)\n"
    "    except OSError:\n"
    "        path.unlink()\n"
    "    return path\n"
)
WRITE_LINE = "            handle.write(data)\n"
REMOVAL_LINE = "        path.unlink()\n"
GUARDED_REMOVAL = (
    "        try:\n"
    "            path.unlink()\n"
    "        except OSError:\n"
    "            pass\n"
)


@pytest.mark.parametrize(
    "source",
    [
        WRITER_SHAPE.replace('"xb"', '"wb"'),
        WRITER_SHAPE.replace('"xb"', '"rb"'),
        WRITER_SHAPE.replace('path.open("xb")', 'open(path, "xb")'),
        WRITER_SHAPE.replace('path.open("xb")', 'path.open("xb", buffering=0)'),
        WRITER_SHAPE.replace('path.open("xb")', 'path.open(mode="xb")'),
        WRITER_SHAPE + 'other = path.open("xb")\n',
        WRITER_SHAPE + "handle.write(data)\n",
        WRITER_SHAPE.replace(WRITE_LINE, WRITE_LINE + WRITE_LINE),
        WRITER_SHAPE.replace(
            WRITE_LINE,
            '            with path.open("xb") as other:\n'
            "                other.write(data)\n",
        ),
        WRITER_SHAPE.replace(WRITE_LINE, "            pass\n"),
        WRITER_SHAPE.replace(WRITE_LINE, "            path.write_bytes(data)\n"),
        WRITER_SHAPE.replace("    return path\n", "    path.parent.mkdir()\n"),
        WRITER_SHAPE.replace("    return path\n", "    other.unlink()\n"),
        WRITER_SHAPE.replace("    return path\n", "    path.replace(other)\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        pass\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, REMOVAL_LINE + REMOVAL_LINE),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        pass\n") + "path.unlink()\n",
        WRITER_SHAPE + "path.unlink()\n",
        WRITER_SHAPE.replace(REMOVAL_LINE, "        other.unlink()\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        path.unlink(missing_ok=True)\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        os.unlink(path)\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        unlink(path)\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        path.parent.unlink()\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, REMOVAL_LINE + "        path.rmdir()\n"),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        path.replace(other)\n"),
        WRITER_SHAPE.replace("write_normalized_container", "write_container"),
        WRITER_SHAPE + WRITER_SHAPE,
        "data = path.read_bytes()\n",
        WRITER_SHAPE + "remove = path.unlink\n",
        WRITER_SHAPE + "from os import unlink as rm\n",
        WRITER_SHAPE + 'handle = getattr(path, "open")("wb")\n',
    ],
)
def test_the_writer_scanner_detects_each_disallowed_shape(source: str) -> None:
    assert _writer_module_violations(ast.parse(source), "synthetic.py") != []


@pytest.mark.parametrize(
    "source",
    [
        WRITER_SHAPE,
        "import hashlib\n\n" + WRITER_SHAPE,
        "data = path.read_bytes()\n" + WRITER_SHAPE,
        WRITER_SHAPE + "\n\ndef digest(data):\n    return sha256(data).hexdigest()\n",
        'def _line(row):\n    return encode(row) + b"\\n"\n' + WRITER_SHAPE,
        WRITER_SHAPE.replace("handle.write(data)", "written = handle.write(data)"),
        WRITER_SHAPE.replace(REMOVAL_LINE, GUARDED_REMOVAL),
        WRITER_SHAPE.replace(REMOVAL_LINE, "        if owned:\n    " + REMOVAL_LINE),
        "def _flag(path):\n    return path.lstat().st_mode\n" + WRITER_SHAPE,
        WRITER_SHAPE.replace(
            "    try:\n",
            "    try:\n        path.parent.lstat()\n        path.lstat()\n",
        ),
    ],
)
def test_the_writer_scanner_admits_each_confined_shape(source: str) -> None:
    assert _writer_module_violations(ast.parse(source), "synthetic.py") == []


COMMAND_SHAPE = (
    "def _prepare_output_directory(output):\n"
    "    try:\n"
    "        output.mkdir()\n"
    "    except OSError:\n"
    "        return False\n"
    "    return True\n"
    "\n"
    "\n"
    "def _write_new_file(path, data, created):\n"
    "    try:\n"
    '        with path.open("xb") as handle:\n'
    "            created.append(path)\n"
    "            handle.write(data)\n"
    "    except OSError:\n"
    "        return False\n"
    "    return True\n"
    "\n"
    "\n"
    "def _remove_created(created):\n"
    "    for path in reversed(created):\n"
    "        try:\n"
    "            path.unlink()\n"
    "        except OSError:\n"
    "            pass\n"
)
MKDIR_LINE = "        output.mkdir()\n"
JSON_OPEN_LINE = '        with path.open("xb") as handle:\n'
JSON_WRITE_LINE = "            handle.write(data)\n"
COMMAND_REMOVAL_LINE = "            path.unlink()\n"
WB_OPEN_LINE = '        with path.open("wb") as handle:\n'
AB_OPEN_LINE = '        with path.open("ab") as handle:\n'
BUILTIN_OPEN_LINE = '        with open(path, "xb") as handle:\n'
BUFFERED_OPEN_LINE = '        with path.open("xb", buffering=0) as handle:\n'
KEYWORD_OPEN_LINE = '        with path.open(mode="xb") as handle:\n'
WRITTEN_LINE = "            written = handle.write(data)\n"
WRITELINES_LINE = "            handle.writelines([data])\n"
WRITE_THEN_UNLINK = JSON_WRITE_LINE + COMMAND_REMOVAL_LINE
RMTREE_LINE = "            shutil.rmtree(path)\n"
REPLACE_LINE = "            path.replace(other)\n"
MISSING_OK_LINE = "            path.unlink(missing_ok=True)\n"
GUARDED_COMMAND_REMOVAL = "            if path in created:\n    " + COMMAND_REMOVAL_LINE
GUARDED_MKDIR = "        if _is_absent(output):\n            output.mkdir()\n"
WITHOUT_MKDIR = COMMAND_SHAPE.replace(MKDIR_LINE, "        pass\n")
WITHOUT_REMOVAL = COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, "            pass\n")


@pytest.mark.parametrize(
    "source",
    [
        COMMAND_SHAPE.replace(MKDIR_LINE, "        output.mkdir(parents=True)\n"),
        COMMAND_SHAPE.replace(MKDIR_LINE, "        output.mkdir(exist_ok=True)\n"),
        COMMAND_SHAPE.replace(MKDIR_LINE, "        output.mkdir(0o700)\n"),
        COMMAND_SHAPE.replace(MKDIR_LINE, "        os.mkdir(output)\n"),
        COMMAND_SHAPE.replace(MKDIR_LINE, "        os.makedirs(output)\n"),
        COMMAND_SHAPE.replace(MKDIR_LINE, "        mkdir(output)\n"),
        COMMAND_SHAPE.replace(MKDIR_LINE, MKDIR_LINE + MKDIR_LINE),
        WITHOUT_MKDIR,
        WITHOUT_MKDIR + "output.mkdir()\n",
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, JSON_WRITE_LINE + MKDIR_LINE),
        COMMAND_SHAPE.replace(JSON_OPEN_LINE, WB_OPEN_LINE),
        COMMAND_SHAPE.replace(JSON_OPEN_LINE, AB_OPEN_LINE),
        COMMAND_SHAPE.replace(JSON_OPEN_LINE, BUILTIN_OPEN_LINE),
        COMMAND_SHAPE.replace(JSON_OPEN_LINE, BUFFERED_OPEN_LINE),
        COMMAND_SHAPE.replace(JSON_OPEN_LINE, KEYWORD_OPEN_LINE),
        COMMAND_SHAPE + 'other = path.open("xb")\n',
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, JSON_WRITE_LINE + JSON_WRITE_LINE),
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, "            pass\n"),
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, "            path.write_bytes(data)\n"),
        COMMAND_SHAPE + "handle.write(data)\n",
        WITHOUT_REMOVAL,
        COMMAND_SHAPE.replace(
            COMMAND_REMOVAL_LINE, COMMAND_REMOVAL_LINE + COMMAND_REMOVAL_LINE
        ),
        COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, "            os.unlink(path)\n"),
        COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, "            unlink(path)\n"),
        COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, MISSING_OK_LINE),
        COMMAND_SHAPE.replace(
            COMMAND_REMOVAL_LINE, COMMAND_REMOVAL_LINE + "            path.rmdir()\n"
        ),
        COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, RMTREE_LINE),
        COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, REPLACE_LINE),
        WITHOUT_REMOVAL + "path.unlink()\n",
        COMMAND_SHAPE + "path.unlink()\n",
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, WRITE_THEN_UNLINK),
        COMMAND_SHAPE.replace("_write_new_file", "_write_file"),
        COMMAND_SHAPE.replace("_prepare_output_directory", "_prepare_output"),
        COMMAND_SHAPE.replace("_remove_created", "_remove"),
        COMMAND_SHAPE + COMMAND_SHAPE,
        COMMAND_SHAPE + "def _prepare_output_directory(output):\n    return True\n",
        "data = path.read_bytes()\n",
        COMMAND_SHAPE + "def helper(path):\n    path.touch()\n",
        COMMAND_SHAPE + "def helper(path):\n    path.rename(other)\n",
        COMMAND_SHAPE + 'parser.add_argument("--out", type=argparse.FileType("w"))\n',
        COMMAND_SHAPE + 'handle = argparse.FileType("w")(path)\n',
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, JSON_WRITE_LINE + WRITELINES_LINE),
        COMMAND_SHAPE + 'from argparse import FileType as FT\nhandle = FT("w")(path)\n',
        COMMAND_SHAPE + "remove = path.unlink\n",
        COMMAND_SHAPE + 'handle = getattr(path, "open")("wb")\n',
    ],
)
def test_the_command_scanner_detects_each_disallowed_shape(source: str) -> None:
    assert _command_module_violations(ast.parse(source), "synthetic.py") != []


@pytest.mark.parametrize(
    "source",
    [
        COMMAND_SHAPE,
        "import argparse\nfrom pathlib import Path\n\n" + COMMAND_SHAPE,
        "data = path.read_bytes()\n" + COMMAND_SHAPE,
        COMMAND_SHAPE
        + "\n\ndef _refused(failure):\n    print(failure)\n    return 1\n",
        COMMAND_SHAPE.replace(JSON_WRITE_LINE, WRITTEN_LINE),
        COMMAND_SHAPE.replace(COMMAND_REMOVAL_LINE, GUARDED_COMMAND_REMOVAL),
        COMMAND_SHAPE.replace(MKDIR_LINE, GUARDED_MKDIR),
        COMMAND_SHAPE.replace(
            "    try:\n        output.mkdir()\n",
            "    try:\n        output.lstat()\n        output.mkdir()\n",
        ),
        COMMAND_SHAPE + "def _is_absent(path):\n    return not path.exists()\n",
    ],
)
def test_the_command_scanner_admits_each_confined_shape(source: str) -> None:
    assert _command_module_violations(ast.parse(source), "synthetic.py") == []


ENTRY_SHAPE = (
    "from crypto_lab_offline_data.cli import normalize_command\n"
    "from crypto_lab_offline_data.providers import SystemClock, Uuid4IdProvider\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    raise SystemExit(\n"
    "        normalize_command(None, ids=Uuid4IdProvider(), clock=SystemClock())\n"
    "    )\n"
)
ENTRY_GUARD_LINE = 'if __name__ == "__main__":\n'
ENTRY_RAISE = (
    "    raise SystemExit(\n"
    "        normalize_command(None, ids=Uuid4IdProvider(), clock=SystemClock())\n"
    "    )\n"
)
UNGUARDED_ENTRY = ENTRY_SHAPE.replace(ENTRY_GUARD_LINE, "").replace("\n    ", "\n")
CHAINED_RAISE = "    raise SystemExit(normalize_command()) from e\n"
TWO_ARGUMENT_RAISE = "    raise SystemExit(normalize_command(), 2)\n"
KEYWORD_RAISE = "    raise SystemExit(code=normalize_command())\n"
PLAIN_RAISE = "    raise SystemExit(normalize_command(None))\n"
MODULE_CALL = "PROVIDER = Uuid4IdProvider()\n"


@pytest.mark.parametrize(
    "source",
    [
        UNGUARDED_ENTRY,
        ENTRY_SHAPE + ENTRY_SHAPE,
        ENTRY_SHAPE.replace(ENTRY_GUARD_LINE, 'if __name__ == "main":\n'),
        ENTRY_SHAPE.replace(ENTRY_GUARD_LINE, 'if __name__ != "__main__":\n'),
        ENTRY_SHAPE.replace(ENTRY_GUARD_LINE, 'if __name__ == "__main__" or True:\n'),
        ENTRY_SHAPE.replace(ENTRY_GUARD_LINE, 'if "__main__" == __name__:\n'),
        ENTRY_SHAPE + "else:\n    pass\n",
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    print('x')\n" + ENTRY_RAISE),
        ENTRY_SHAPE.replace(ENTRY_RAISE, ENTRY_RAISE + "    print('x')\n"),
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    main()\n"),
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    raise SystemExit(main())\n"),
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    raise SystemExit(1)\n"),
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    raise SystemExit(normalize_command)\n"),
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    sys.exit(normalize_command(None))\n"),
        ENTRY_SHAPE.replace(
            ENTRY_RAISE, "    raise RuntimeError(normalize_command())\n"
        ),
        ENTRY_SHAPE.replace(ENTRY_RAISE, CHAINED_RAISE),
        ENTRY_SHAPE.replace(ENTRY_RAISE, TWO_ARGUMENT_RAISE),
        ENTRY_SHAPE.replace(ENTRY_RAISE, KEYWORD_RAISE),
        MODULE_CALL + ENTRY_SHAPE,
        ENTRY_SHAPE + "CLOCK = SystemClock()\n",
        ENTRY_SHAPE.replace(ENTRY_GUARD_LINE, MODULE_CALL + ENTRY_GUARD_LINE),
    ],
)
def test_the_entry_point_scanner_detects_each_disallowed_shape(source: str) -> None:
    assert _entry_point_violations(ast.parse(source), "synthetic.py") != []


@pytest.mark.parametrize(
    "source",
    [
        ENTRY_SHAPE,
        '"""Docstring."""\n\n' + ENTRY_SHAPE,
        "from __future__ import annotations\n\n" + ENTRY_SHAPE,
        ENTRY_SHAPE.replace(ENTRY_RAISE, PLAIN_RAISE),
        ENTRY_SHAPE.replace(ENTRY_RAISE, "    raise SystemExit(normalize_command())\n"),
        "import re\nPATTERN = re.compile('x')\n" + ENTRY_SHAPE,
    ],
)
def test_the_entry_point_scanner_admits_each_confined_shape(source: str) -> None:
    assert _entry_point_violations(ast.parse(source), "synthetic.py") == []


@pytest.mark.parametrize("family", PROHIBITED_FAMILIES)
def test_the_family_matcher_rejects_every_prohibited_family(family: str) -> None:
    assert _is_prohibited(f"vendor-{family}-client>=1")
    assert len(PROHIBITED_FAMILIES) == 27


@pytest.mark.parametrize(
    ("requirement", "normalized"),
    [
        ("nautilus_trader>=1", "nautilus-trader"),
        ("IB.Insync[all]>=1; python_version >= '3.12'", "ib-insync"),
        ("requests @ https://invalid.example/package.whl", "requests"),
        ("crypto-trading-lab", "crypto-trading-lab"),
    ],
)
def test_requirement_name_normalization(requirement: str, normalized: str) -> None:
    assert _normalized_requirement_name(requirement) == normalized


class TestDependencyPins:
    """Section 2.6 pin and lock guards: one selector runs exactly these.

    Operator negative control: alter one dev-group pin line in
    ``offline_data/pyproject.toml`` and one ``version = `` line in
    ``offline_data/uv.lock``; the dev-group test and the lock-version test fail
    when the class is run through the launcher selector, and both files are
    then restored byte for byte before any worker GREEN.
    """

    def test_runtime_dependencies_are_exactly_the_core_path_dependency(
        self,
        sub_project_root: Path,
    ) -> None:
        document = _load_toml(sub_project_root / "pyproject.toml")
        project = document["project"]

        assert project["dependencies"] == EXPECTED_RUNTIME_DEPENDENCIES
        assert "optional-dependencies" not in project
        assert project["requires-python"] == EXPECTED_REQUIRES_PYTHON
        assert document["tool"]["uv"]["sources"] == EXPECTED_SOURCES

    def test_the_dev_group_pins_equal_the_approved_closure(
        self,
        sub_project_root: Path,
    ) -> None:
        document = _load_toml(sub_project_root / "pyproject.toml")

        assert document["dependency-groups"] == {"dev": EXPECTED_DEV_GROUP}
        assert document["build-system"]["requires"] == EXPECTED_BUILD_REQUIRES

    def test_the_constraint_dependencies_equal_the_approved_runtime_closure(
        self,
        sub_project_root: Path,
    ) -> None:
        document = _load_toml(sub_project_root / "pyproject.toml")
        uv = document["tool"]["uv"]

        assert uv["constraint-dependencies"] == EXPECTED_CONSTRAINTS
        assert uv["no-build-isolation"] is True
        assert uv["python-downloads"] == "manual"
        assert uv["python-preference"] == "only-managed"

    def test_the_lock_records_every_package_at_the_approved_version(
        self,
        sub_project_root: Path,
    ) -> None:
        lock = _load_toml(sub_project_root / "uv.lock")
        packages = lock["package"]

        versions = {package["name"]: package["version"] for package in packages}

        expected = [_pinned_name_and_specifier(r) for r in EXPECTED_CONSTRAINTS]

        assert versions == EXPECTED_LOCKED_VERSIONS
        assert len(packages) == len(EXPECTED_LOCKED_VERSIONS)
        assert lock["requires-python"] == EXPECTED_LOCK_REQUIRES_PYTHON
        assert lock["manifest"]["constraints"] == expected

    def test_the_lock_records_the_core_as_a_directory_source(
        self,
        sub_project_root: Path,
    ) -> None:
        lock = _load_toml(sub_project_root / "uv.lock")
        packages = {package["name"]: package for package in lock["package"]}
        core = packages["crypto-trading-lab"]
        own = packages["crypto-lab-offline-data"]
        core_dependency_names = {entry["name"] for entry in core["dependencies"]}
        core_distribution_names = {
            entry["name"] for entry in core["metadata"]["requires-dist"]
        }
        own_dependency_names = [entry["name"] for entry in own["dependencies"]]
        expected_requires_dist = [{"name": "crypto-trading-lab", "directory": "../"}]

        assert core["source"] == {"directory": "../"}
        assert core_dependency_names == EXPECTED_CORE_RUNTIME_NAMES
        assert core_distribution_names == EXPECTED_CORE_RUNTIME_NAMES
        assert own["source"] == {"editable": "."}
        assert own_dependency_names == EXPECTED_RUNTIME_DEPENDENCIES
        assert own["metadata"]["requires-dist"] == expected_requires_dist

    def test_every_registry_package_is_pypi_and_sha256_pinned(
        self,
        sub_project_root: Path,
    ) -> None:
        lock = _load_toml(sub_project_root / "uv.lock")

        for package in lock["package"]:
            if package["name"] in LOCAL_PACKAGES:
                continue
            assert package["source"] == {"registry": PYPI_REGISTRY}, package["name"]
            artifacts = [*package.get("wheels", [])]
            if "sdist" in package:
                artifacts.append(package["sdist"])
            assert artifacts, package["name"]
            for artifact in artifacts:
                digest = artifact["hash"]
                assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None

    def test_no_prohibited_family_is_declared_or_locked(
        self,
        sub_project_root: Path,
    ) -> None:
        document = _load_toml(sub_project_root / "pyproject.toml")
        lock = _load_toml(sub_project_root / "uv.lock")
        declared = [
            *document["project"]["dependencies"],
            *document["dependency-groups"]["dev"],
            *document["tool"]["uv"]["constraint-dependencies"],
            *document["build-system"]["requires"],
            *document["tool"]["uv"]["sources"],
            *(package["name"] for package in lock["package"]),
        ]

        assert [name for name in declared if _is_prohibited(name)] == []

    def test_the_coverage_floor_and_test_options_are_pinned(
        self,
        sub_project_root: Path,
    ) -> None:
        document = _load_toml(sub_project_root / "pyproject.toml")
        pytest_options = document["tool"]["pytest"]["ini_options"]

        assert pytest_options["addopts"] == EXPECTED_ADDOPTS
        assert pytest_options["testpaths"] == ["tests"]
        assert document["tool"]["coverage"]["report"] == EXPECTED_COVERAGE_REPORT
        assert document["tool"]["coverage"]["run"] == EXPECTED_COVERAGE_RUN
