"""The ``DatasetRepository`` port (Stage 8 plan reading 12; Task 3).

A plan-introduced extension of specification 8.2: ``get_by_hash`` and
``list_partitions`` are the specification's two reads and ``register`` is the
idempotent registration reading 12 adds ("an existing content hash is reused
idempotently", spec 18.3). The port is a ``runtime_checkable`` ``Protocol`` in
``crypto_lab.datasets.ports`` that imports only ``domain`` and its own package's
models, exported by the ``datasets`` package in the sorted ``__all__`` groups the
repository uses. Nothing here touches a database: the concrete
``SqliteDatasetRepository`` is proven against the port in the persistence suite.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Final, get_type_hints

import crypto_lab.datasets as datasets_package
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.datasets.ports import DatasetRepository
from crypto_lab.domain.results import Result, Success

_PORT_MODULE: Final = (
    Path(__file__).resolve().parents[3] / "src/crypto_lab/datasets/ports.py"
)
#: The port module may reach ``domain`` and its own package only (plan Task 3).
_ALLOWED_PROJECT_PREFIXES: Final = ("crypto_lab.domain", "crypto_lab.datasets")
_ALLOWED_STDLIB_ROOTS: Final = frozenset({"__future__", "typing"})


def _members(port: type) -> set[str]:
    return {
        name
        for name, value in vars(port).items()
        if not name.startswith("_") and (callable(value) or isinstance(value, property))
    }


class _Conforming:
    """A structural stub carrying exactly the three port members."""

    def get_by_hash(self, content_hash: str) -> Result[DatasetDescriptor]:
        raise NotImplementedError(content_hash)

    def list_partitions(self, dataset_id: str) -> Result[tuple[DatasetPartition, ...]]:
        del dataset_id
        return Success[tuple[DatasetPartition, ...]](outcome="SUCCESS", value=())

    def register(
        self,
        descriptor: DatasetDescriptor,
        partitions: tuple[DatasetPartition, ...],
    ) -> Result[None]:
        del descriptor, partitions
        return Success[None](outcome="SUCCESS", value=None)


class _Reader:
    """The two specification reads without the plan-introduced ``register``."""

    def get_by_hash(self, content_hash: str) -> Result[DatasetDescriptor]:
        raise NotImplementedError(content_hash)

    def list_partitions(self, dataset_id: str) -> Result[tuple[DatasetPartition, ...]]:
        del dataset_id
        return Success[tuple[DatasetPartition, ...]](outcome="SUCCESS", value=())


def test_the_port_carries_exactly_the_reading_twelve_members() -> None:
    assert _members(DatasetRepository) == {"get_by_hash", "list_partitions", "register"}


def test_the_port_is_a_runtime_checkable_structural_protocol() -> None:
    assert isinstance(_Conforming(), DatasetRepository)
    assert not isinstance(_Reader(), DatasetRepository)
    assert not isinstance(object(), DatasetRepository)


def test_the_port_signatures_are_the_reading_twelve_shapes() -> None:
    get_by_hash = inspect.signature(DatasetRepository.get_by_hash)
    assert tuple(get_by_hash.parameters) == ("self", "content_hash")
    list_partitions = inspect.signature(DatasetRepository.list_partitions)
    assert tuple(list_partitions.parameters) == ("self", "dataset_id")
    register = inspect.signature(DatasetRepository.register)
    assert tuple(register.parameters) == ("self", "descriptor", "partitions")
    hints = get_type_hints(DatasetRepository.get_by_hash)
    assert hints["return"].__origin__ is Result
    assert hints["return"].__args__ == (DatasetDescriptor,)
    hints = get_type_hints(DatasetRepository.list_partitions)
    assert hints["return"].__origin__ is Result
    assert hints["return"].__args__ == (tuple[DatasetPartition, ...],)
    hints = get_type_hints(DatasetRepository.register)
    assert hints["return"].__origin__ is Result
    assert hints["return"].__args__ == (None,)  # the PEP 695 alias keeps the literal
    assert hints["descriptor"] is DatasetDescriptor
    assert hints["partitions"] == tuple[DatasetPartition, ...]


def test_the_port_module_and_the_package_export_are_pinned() -> None:
    assert DatasetRepository.__module__ == "crypto_lab.datasets.ports"
    exported = datasets_package.__all__
    assert "DatasetRepository" in exported
    assert datasets_package.DatasetRepository is DatasetRepository
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
