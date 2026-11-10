"""Closed-world guards of the ``offline_data`` sub-project (plan section 2.6).

Two guard families live here. The source guards pin the Task 1 package census,
the import roots the package may use, the absence of environment, network and
process reach, import-time purity and the reader's no-write rule, and they prove
at run time that reading a fixture changes neither its bytes nor any directory.
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
import hashlib
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

PACKAGE = "crypto_lab_offline_data"
EXPECTED_MODULES = ("__init__.py", "candle_csv.py", "diagnostics.py", "providers.py")
ALLOWED_IMPORT_ROOTS = {
    PACKAGE,
    "__future__",
    "crypto_lab",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
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
WRITE_ATTRIBUTES = {
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
}
READ_ONLY_OPEN_MODE = "rb"

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


def _write_call_violations(tree: ast.AST, relative_path: str) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee: str | None
        if isinstance(node.func, ast.Attribute):
            callee = node.func.attr
        else:
            callee = _qualified_name(node.func)
        if callee in WRITE_ATTRIBUTES:
            violations.append(f"{relative_path}:{node.lineno}: write call {callee}")
        if callee == "open":
            modes = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
            exact = len(node.args) == 1 and modes == [READ_ONLY_OPEN_MODE]
            if not exact or node.keywords:
                violations.append(
                    f"{relative_path}:{node.lineno}: open is not exactly open('rb')"
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


def test_the_package_census_is_exactly_the_task_one_modules(
    sub_project_root: Path,
) -> None:
    """Task 2 extends this tuple when it adds its modules; nothing else may."""
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
    """Import time may compile patterns and declare dataclasses, nothing else."""
    failures: list[str] = []
    for path in _expected_module_paths(sub_project_root):
        failures.extend(_import_time_call_violations(_parse(path), path.name))

    assert failures == []


def test_no_module_contains_a_write_call(sub_project_root: Path) -> None:
    failures: list[str] = []
    for path in _expected_module_paths(sub_project_root):
        failures.extend(_write_call_violations(_parse(path), path.name))

    assert failures == []


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
    ],
)
def test_the_write_scanner_admits_each_read_only_shape(source: str) -> None:
    assert _write_call_violations(ast.parse(source), "synthetic.py") == []


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
