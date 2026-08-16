"""Keep Project 1 dependencies minimal, exact, and engine-free."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

_PROHIBITED_FAMILIES: tuple[str, ...] = (
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
    "sqlalchemy",
    "alembic",
    "pyarrow",
    "pandas",
    "polars",
    "numpy",
    "ollama",
    "openai",
)
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EXPECTED_RUNTIME_REQUIREMENTS = (
    "pydantic>=2.12,<3",
    "pyyaml>=6.0.3,<7",
)
_EXPECTED_DEVELOPMENT_NAMES = {
    "hatchling",
    "hypothesis",
    "jsonschema",
    "mypy",
    "pytest",
    "pytest-cov",
    "ruff",
    "types-pyyaml",
}


@dataclass(frozen=True, order=True, slots=True)
class RuntimeDependency:
    """One dependency declared in a PEP 621 runtime group."""

    group: str
    requirement: str


def _mapping(value: object, location: str) -> Mapping[str, object]:
    assert isinstance(value, dict), f"{location} must be a table"
    assert all(isinstance(key, str) for key in value), (
        f"{location} keys must be strings"
    )
    return cast(dict[str, object], value)


def _string_list(value: object, location: str) -> tuple[str, ...]:
    assert isinstance(value, list), f"{location} must be an array"
    assert all(isinstance(item, str) for item in value), (
        f"{location} entries must be strings"
    )
    return tuple(cast(list[str], value))


def _load_pyproject(path: Path) -> Mapping[str, object]:
    return cast(dict[str, object], tomllib.loads(path.read_text(encoding="utf-8")))


def runtime_dependencies(
    document: Mapping[str, object],
) -> tuple[RuntimeDependency, ...]:
    """Return PEP 621 default and optional runtime dependencies only."""
    project = _mapping(document.get("project"), "[project]")
    dependencies = [
        RuntimeDependency(
            group="project.dependencies",
            requirement=requirement,
        )
        for requirement in _string_list(
            project.get("dependencies"),
            "project.dependencies",
        )
    ]
    optional_groups = _mapping(
        project.get("optional-dependencies", {}),
        "project.optional-dependencies",
    )
    for group_name in sorted(optional_groups):
        requirements = _string_list(
            optional_groups[group_name],
            f"project.optional-dependencies.{group_name}",
        )
        dependencies.extend(
            RuntimeDependency(
                group=f"project.optional-dependencies.{group_name}",
                requirement=requirement,
            )
            for requirement in requirements
        )
    return tuple(dependencies)


def _normalized_requirement_name(requirement: str) -> str:
    match = _REQUIREMENT_NAME.match(requirement)
    assert match is not None, f"Cannot parse dependency name from {requirement!r}"
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def prohibited_runtime_dependencies(
    dependencies: tuple[RuntimeDependency, ...],
) -> tuple[RuntimeDependency, ...]:
    """Return runtime dependencies containing a prohibited normalized family."""
    return tuple(
        sorted(
            dependency
            for dependency in dependencies
            if any(
                family in _normalized_requirement_name(dependency.requirement)
                for family in _PROHIBITED_FAMILIES
            )
        )
    )


def test_project_runtime_dependencies_are_exact(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")

    assert (
        tuple(dependency.requirement for dependency in runtime_dependencies(document))
        == _EXPECTED_RUNTIME_REQUIREMENTS
    )


def test_project_has_no_prohibited_runtime_dependency(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")

    assert prohibited_runtime_dependencies(runtime_dependencies(document)) == ()


def test_optional_runtime_dependencies_are_extracted_and_rejected() -> None:
    document: dict[str, object] = {
        "project": {
            "dependencies": [],
            "optional-dependencies": {
                "exchange": ["Binance.Client>=1"],
            },
        }
    }
    expected = (
        RuntimeDependency(
            group="project.optional-dependencies.exchange",
            requirement="Binance.Client>=1",
        ),
    )

    extracted = runtime_dependencies(document)

    assert extracted == expected
    assert prohibited_runtime_dependencies(extracted) == expected


@pytest.mark.parametrize("family", _PROHIBITED_FAMILIES)
def test_matcher_rejects_every_prohibited_family(family: str) -> None:
    dependency = RuntimeDependency(
        group="project.dependencies",
        requirement=f"vendor-{family}-client>=1",
    )

    assert prohibited_runtime_dependencies((dependency,)) == (dependency,)


@pytest.mark.parametrize(
    ("requirement", "normalized"),
    [
        ("nautilus_trader>=1", "nautilus-trader"),
        ("IB.Insync[all]>=1; python_version >= '3.12'", "ib-insync"),
        ("requests @ https://invalid.example/package.whl", "requests"),
    ],
)
def test_requirement_name_normalization(
    requirement: str,
    normalized: str,
) -> None:
    assert _normalized_requirement_name(requirement) == normalized


def test_development_and_build_dependencies_are_not_runtime_dependencies() -> None:
    document: dict[str, object] = {
        "project": {"dependencies": []},
        "dependency-groups": {
            "dev": ["hatchling", "pytest", "pytest-cov", "ruff", "mypy"]
        },
        "build-system": {"requires": ["hatchling"]},
    }

    assert runtime_dependencies(document) == ()


def test_required_development_tools_are_declared(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")
    groups = _mapping(document.get("dependency-groups"), "dependency-groups")
    dev_requirements = _string_list(groups.get("dev"), "dependency-groups.dev")
    declared = {_normalized_requirement_name(item) for item in dev_requirements}

    assert declared == _EXPECTED_DEVELOPMENT_NAMES


def test_lock_registry_artifacts_are_sha256_pinned(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "uv.lock")
    packages = document.get("package")
    assert isinstance(packages, list)
    for package in packages:
        package_table = _mapping(package, "package entry")
        name = package_table.get("name")
        assert isinstance(name, str)
        source = _mapping(package_table.get("source"), "package source")
        if name == "crypto-trading-lab":
            assert source == {"editable": "."}
            continue
        assert set(source) == {"registry"}
        assert source["registry"] == "https://pypi.org/simple"
        wheels = package_table.get("wheels", [])
        assert isinstance(wheels, list)
        artifacts: list[object] = list(wheels)
        sdist = package_table.get("sdist")
        if sdist is not None:
            artifacts = [sdist, *artifacts]
        assert artifacts, package_table["name"]
        for artifact in artifacts:
            artifact_table = _mapping(artifact, "locked artifact")
            digest = artifact_table.get("hash")
            assert isinstance(digest, str)
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None


def test_locked_yaml_packages_are_typed_and_ship_a_cp312_wheel(
    repository_root: Path,
) -> None:
    """Reject a stub-less install and an sdist-only PyYAML.

    ``test_lock_registry_artifacts_are_sha256_pinned`` does not distinguish an
    sdist from a wheel, and ``no-build-isolation = true`` means an sdist path
    would run PyYAML's ``setup.py`` against the project environment.
    """
    document = _load_pyproject(repository_root / "uv.lock")
    packages = document.get("package")
    assert isinstance(packages, list)
    locked = {
        str(_mapping(package, "package entry").get("name")): _mapping(
            package,
            "package entry",
        )
        for package in packages
    }

    assert "types-pyyaml" in locked

    wheels = locked["pyyaml"].get("wheels")
    assert isinstance(wheels, list)
    urls = [str(_mapping(wheel, "locked wheel").get("url")) for wheel in wheels]

    assert any("cp312" in url and "win_amd64" in url for url in urls)


def test_mypy_untyped_import_override_is_exact(repository_root: Path) -> None:
    document = _load_pyproject(repository_root / "pyproject.toml")
    tool = _mapping(document.get("tool"), "[tool]")
    mypy = _mapping(tool.get("mypy"), "[tool.mypy]")
    # Pinning only ``overrides`` would let a top-level
    # ``ignore_missing_imports`` or ``disable_error_code`` relax typing
    # repository-wide while leaving this test green.
    assert set(mypy) == {"python_version", "strict", "files", "overrides"}
    assert mypy.get("overrides") == [
        {
            "module": ["jsonschema", "jsonschema.*"],
            "ignore_missing_imports": True,
        }
    ]
