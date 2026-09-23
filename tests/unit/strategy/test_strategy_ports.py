"""The ``StrategyVersionRepository`` port (Stage 8 plan reading 12; Task 3).

A plan-introduced port (specification 8.2 names none for strategy versions; the
table is specification 23.3.1's) carrying ``get_by_hash`` and the idempotent
``register``. The port is a ``runtime_checkable`` ``Protocol`` in
``crypto_lab.strategy.ports`` that imports only ``domain`` and its own package's
records, exported by the ``strategy`` package in the sorted ``__all__`` groups the
repository uses. Nothing here touches a database: the concrete
``SqliteStrategyVersionRepository`` is proven against the port in the persistence
suite.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Final, get_type_hints

import crypto_lab.strategy as strategy_package
from crypto_lab.domain.results import Result, Success
from crypto_lab.strategy.ports import StrategyVersionRepository
from crypto_lab.strategy.versioning import StrategyVersion

_PORT_MODULE: Final = (
    Path(__file__).resolve().parents[3] / "src/crypto_lab/strategy/ports.py"
)
#: The port module may reach ``domain`` and its own package only (plan Task 3).
_ALLOWED_PROJECT_PREFIXES: Final = ("crypto_lab.domain", "crypto_lab.strategy")
_ALLOWED_STDLIB_ROOTS: Final = frozenset({"__future__", "typing"})


def _members(port: type) -> set[str]:
    return {
        name
        for name, value in vars(port).items()
        if not name.startswith("_") and (callable(value) or isinstance(value, property))
    }


class _Conforming:
    """A structural stub carrying exactly the two port members."""

    def get_by_hash(self, content_hash: str) -> Result[StrategyVersion]:
        raise NotImplementedError(content_hash)

    def register(self, version: StrategyVersion) -> Result[None]:
        del version
        return Success[None](outcome="SUCCESS", value=None)


class _ReadOnly:
    """The read without the registration."""

    def get_by_hash(self, content_hash: str) -> Result[StrategyVersion]:
        raise NotImplementedError(content_hash)


def test_the_port_carries_exactly_the_reading_twelve_members() -> None:
    assert _members(StrategyVersionRepository) == {"get_by_hash", "register"}


def test_the_port_is_a_runtime_checkable_structural_protocol() -> None:
    assert isinstance(_Conforming(), StrategyVersionRepository)
    assert not isinstance(_ReadOnly(), StrategyVersionRepository)
    assert not isinstance(object(), StrategyVersionRepository)


def test_the_port_signatures_are_the_reading_twelve_shapes() -> None:
    get_by_hash = inspect.signature(StrategyVersionRepository.get_by_hash)
    assert tuple(get_by_hash.parameters) == ("self", "content_hash")
    register = inspect.signature(StrategyVersionRepository.register)
    assert tuple(register.parameters) == ("self", "version")
    hints = get_type_hints(StrategyVersionRepository.get_by_hash)
    assert hints["return"].__origin__ is Result
    assert hints["return"].__args__ == (StrategyVersion,)
    hints = get_type_hints(StrategyVersionRepository.register)
    assert hints["return"].__origin__ is Result
    assert hints["return"].__args__ == (None,)  # the PEP 695 alias keeps the literal
    assert hints["version"] is StrategyVersion


def test_the_port_module_and_the_package_export_are_pinned() -> None:
    assert StrategyVersionRepository.__module__ == "crypto_lab.strategy.ports"
    exported = strategy_package.__all__
    assert "StrategyVersionRepository" in exported
    assert strategy_package.StrategyVersionRepository is StrategyVersionRepository
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)


def test_the_port_module_imports_only_domain_and_its_own_package() -> None:
    tree = ast.parse(_PORT_MODULE.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            imported.append(node.module)
    assert imported
    for name in imported:
        root = name.partition(".")[0]
        if root == "crypto_lab":
            assert name.startswith(_ALLOWED_PROJECT_PREFIXES), name
        else:
            assert root in _ALLOWED_STDLIB_ROOTS, name
