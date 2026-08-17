"""Stage 4 YAML runtime guards.

This module imports ``yaml`` deliberately and is the only safety module that
may. Keeping it separate from ``tests/safety/test_stage4_boundaries.py`` means
the source-level guards there stay collectable before PyYAML is installed.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

import yaml

from crypto_lab.strategy.yaml_source import StrictStrategySafeLoader

if TYPE_CHECKING:
    from pathlib import Path

# Directory-scoped rather than a closed module list, because only Tasks 1 and 2
# own this file while later Stage 4 tasks keep adding modules to these packages.
_DETERMINISM_SCOPED_PACKAGES = ("strategy", "capabilities")
_NONDETERMINISTIC_IMPORT_ROOTS = frozenset({"random", "time", "uuid"})

# Thirteen entries: the twelve ``tag:yaml.org,2002:`` tags plus the ``None``
# key that ``SafeConstructor.add_constructor(None,
# SafeConstructor.construct_undefined)`` registers. Omitting ``None`` produces
# a failure that reads like a supply-chain alarm rather than a test bug.
_EXPECTED_SAFELOADER_TAGS = frozenset(
    {
        None,
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:binary",
        "tag:yaml.org,2002:timestamp",
        "tag:yaml.org,2002:omap",
        "tag:yaml.org,2002:pairs",
        "tag:yaml.org,2002:set",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:map",
    }
)


def test_safeloader_constructor_tags_are_exactly_expected() -> None:
    """Catch a third-party ``yaml.YAMLObject`` or constructor registration.

    The assertion is absolute rather than a before/after comparison, because a
    comparison is structurally incapable of detecting a class-body or
    import-time mutation that already ran.
    """
    assert frozenset(yaml.SafeLoader.yaml_constructors) == _EXPECTED_SAFELOADER_TAGS


def test_the_strict_loader_owns_no_constructor_or_resolver_state() -> None:
    """The subclass body is empty, so it never triggers copy-on-write.

    An unqualified ``StrictStrategySafeLoader.yaml_constructors[t] = f`` would
    mutate the **inherited** ``yaml.SafeLoader`` dict, because the subclass does
    not own that attribute until PyYAML's copy-on-write ``add_constructor``
    runs. Identity against the parent dict proves no such call happened.
    """
    for attribute in (
        "yaml_constructors",
        "yaml_multi_constructors",
        "yaml_implicit_resolvers",
    ):
        assert attribute not in StrictStrategySafeLoader.__dict__

    assert yaml.SafeLoader in StrictStrategySafeLoader.__mro__
    parent_constructors = yaml.SafeLoader.yaml_constructors
    assert StrictStrategySafeLoader.yaml_constructors is parent_constructors


def _imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    return roots


def test_yaml_is_imported_by_exactly_one_source_module(repository_root: Path) -> None:
    """Section 5.2's single-importer contract, asserted against the filesystem."""
    source_root = repository_root / "src" / "crypto_lab"
    importers = {
        path.relative_to(source_root).as_posix()
        for path in sorted(source_root.rglob("*.py"))
        if "yaml" in _imported_roots(ast.parse(path.read_text(encoding="utf-8")))
    }

    assert importers == {"strategy/yaml_source.py"}


def test_no_strategy_or_capability_module_reads_a_nondeterministic_source(
    repository_root: Path,
) -> None:
    """Section 5.3.3: identity is derived and time is a parameter, never drawn."""
    source_root = repository_root / "src" / "crypto_lab"
    offenders: list[str] = []
    for package in _DETERMINISM_SCOPED_PACKAGES:
        for path in sorted((source_root / package).rglob("*.py")):
            roots = _imported_roots(ast.parse(path.read_text(encoding="utf-8")))
            offenders.extend(
                f"{path.relative_to(source_root).as_posix()}: {root}"
                for root in sorted(roots & _NONDETERMINISTIC_IMPORT_ROOTS)
            )

    assert offenders == []


def test_the_determinism_scan_detects_a_nondeterministic_import() -> None:
    """A positive control, so the guard above cannot pass vacuously."""
    for source in ("import random", "import time as clock", "import uuid"):
        detected = _imported_roots(ast.parse(source)) & _NONDETERMINISTIC_IMPORT_ROOTS
        assert detected != set(), source

    benign = _imported_roots(ast.parse("import json"))
    assert benign & _NONDETERMINISTIC_IMPORT_ROOTS == set()
