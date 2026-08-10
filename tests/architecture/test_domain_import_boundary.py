"""Enforce the domain package import boundary with the standard-library AST."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from importlib.util import resolve_name
from pathlib import Path

import pytest

_PROHIBITED_PROJECT_PACKAGES: tuple[str, ...] = (
    "crypto_lab.strategy",
    "crypto_lab.capabilities",
    "crypto_lab.adapters",
    "crypto_lab.experiments",
    "crypto_lab.datasets",
    "crypto_lab.artifacts",
    "crypto_lab.persistence",
    "crypto_lab.process_supervision",
    "crypto_lab.configuration",
    "crypto_lab.audit",
    "crypto_lab.cli",
)


@dataclass(frozen=True, order=True, slots=True)
class ImportViolation:
    """One prohibited import found in a domain source file."""

    relative_path: str
    line_number: int
    imported_name: str


def _source_package_name(source_path: Path, domain_root: Path) -> str:
    relative_parts = list(source_path.relative_to(domain_root).with_suffix("").parts)
    relative_parts.pop()
    return ".".join(("crypto_lab", "domain", *relative_parts))


def _imported_names(
    node: ast.Import | ast.ImportFrom,
    package_name: str,
) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)

    imported_base = node.module or ""
    if node.level > 0:
        imported_base = resolve_name("." * node.level + imported_base, package_name)

    if imported_base == "crypto_lab":
        return tuple(f"crypto_lab.{alias.name}" for alias in node.names)
    return (imported_base,)


def _is_prohibited(imported_name: str) -> bool:
    return any(
        imported_name == package_name or imported_name.startswith(f"{package_name}.")
        for package_name in _PROHIBITED_PROJECT_PACKAGES
    )


def find_domain_import_violations(domain_root: Path) -> tuple[ImportViolation, ...]:
    """Return prohibited imports below the supplied domain package root."""
    violations: list[ImportViolation] = []
    source_paths = sorted(domain_root.rglob("*.py"), key=lambda path: path.as_posix())

    for source_path in source_paths:
        source = source_path.read_text(encoding="utf-8")
        syntax_tree = ast.parse(source, filename=str(source_path))
        package_name = _source_package_name(source_path, domain_root)
        for node in ast.walk(syntax_tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for imported_name in _imported_names(node, package_name):
                if _is_prohibited(imported_name):
                    violations.append(
                        ImportViolation(
                            relative_path=source_path.relative_to(
                                domain_root
                            ).as_posix(),
                            line_number=node.lineno,
                            imported_name=imported_name,
                        )
                    )

    return tuple(sorted(violations))


def _write_domain_source(tmp_path: Path, source: str) -> Path:
    domain_root = tmp_path / "src" / "crypto_lab" / "domain"
    domain_root.mkdir(parents=True)
    (domain_root / "sample.py").write_text(source, encoding="utf-8")
    return domain_root


@pytest.mark.parametrize("package_name", _PROHIBITED_PROJECT_PACKAGES)
def test_scanner_rejects_every_prohibited_package(
    tmp_path: Path,
    package_name: str,
) -> None:
    domain_root = _write_domain_source(tmp_path, f"import {package_name}\n")

    violations = find_domain_import_violations(domain_root)

    assert tuple(item.imported_name for item in violations) == (package_name,)


@pytest.mark.parametrize(
    ("statement", "expected_name"),
    [
        ("import crypto_lab.persistence", "crypto_lab.persistence"),
        (
            "import crypto_lab.persistence.repositories",
            "crypto_lab.persistence.repositories",
        ),
        ("from crypto_lab import persistence", "crypto_lab.persistence"),
        (
            "from crypto_lab.persistence import repositories",
            "crypto_lab.persistence",
        ),
        ("import crypto_lab.persistence as storage", "crypto_lab.persistence"),
        (
            "import crypto_lab.persistence.repositories as repositories",
            "crypto_lab.persistence.repositories",
        ),
        ("from crypto_lab import persistence as storage", "crypto_lab.persistence"),
        (
            "from crypto_lab.persistence import repositories as repositories",
            "crypto_lab.persistence",
        ),
    ],
)
def test_scanner_rejects_each_absolute_import_shape(
    tmp_path: Path,
    statement: str,
    expected_name: str,
) -> None:
    domain_root = _write_domain_source(tmp_path, f"{statement}\n")

    violations = find_domain_import_violations(domain_root)

    assert tuple(item.imported_name for item in violations) == (expected_name,)


def test_scanner_rejects_relative_import_that_escapes_domain(tmp_path: Path) -> None:
    domain_root = _write_domain_source(tmp_path, "from .. import persistence\n")

    violations = find_domain_import_violations(domain_root)

    assert tuple(item.imported_name for item in violations) == (
        "crypto_lab.persistence",
    )


def test_scanner_recurses_into_nested_domain_packages(tmp_path: Path) -> None:
    domain_root = tmp_path / "src" / "crypto_lab" / "domain"
    nested_root = domain_root / "nested"
    nested_root.mkdir(parents=True)
    (nested_root / "sample.py").write_text(
        "import crypto_lab.persistence\n",
        encoding="utf-8",
    )

    violations = find_domain_import_violations(domain_root)

    assert violations == (
        ImportViolation(
            relative_path="nested/sample.py",
            line_number=1,
            imported_name="crypto_lab.persistence",
        ),
    )


def test_scanner_ignores_non_import_text_and_allowed_imports(tmp_path: Path) -> None:
    domain_root = _write_domain_source(
        tmp_path,
        '''"""import crypto_lab.persistence inside a string."""
# from crypto_lab import persistence
import datetime
import external_library
from . import sibling
from .nested import helper
''',
    )

    assert find_domain_import_violations(domain_root) == ()


def test_repository_domain_package_has_no_prohibited_imports(
    repository_root: Path,
) -> None:
    domain_root = repository_root / "src" / "crypto_lab" / "domain"

    assert find_domain_import_violations(domain_root) == ()
