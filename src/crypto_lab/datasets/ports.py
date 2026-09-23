"""The dataset registry port (Stage 8 plan reading 12; specification 8.2, 18.3).

Specification 8.2 places the ``DatasetRepository`` protocol in the package that
owns the records it persists and gives it two reads, ``get_by_hash`` and
``list_partitions``; the Stage 8 plan adds ``register``, the idempotent
registration specification 18.3 describes ("an existing content hash is reused
idempotently"). Every method is synchronous and returns ``Result[...]``: a
missing identity is a ``Failure`` carrying ``CORE.INVARIANT_VIOLATION`` (the
Stage 5 port convention), ``register`` validates the descriptor against its
partitions through ``validate_dataset_identity`` before any statement, an
identical content hash already registered is an idempotent ``Success``, and a
different descriptor under the same hash is ``CORE.INVARIANT_VIOLATION``. A
repository never commits on its own; the caller owns the transaction.

The module imports ``domain`` and its own package only (plan Task 3); the
concrete implementation lives in ``crypto_lab.persistence`` (Stage 8) and the
application never imports it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.identifiers import DatasetId, Sha256
from crypto_lab.domain.results import Result

__all__ = ["DatasetRepository"]


@runtime_checkable
class DatasetRepository(Protocol):
    """Immutable dataset metadata by content identity (specification 8.2, 18.3)."""

    def get_by_hash(self, content_hash: Sha256) -> Result[DatasetDescriptor]:
        """The descriptor registered under ``content_hash``; absent is a ``Failure``."""

    def list_partitions(
        self, dataset_id: DatasetId
    ) -> Result[tuple[DatasetPartition, ...]]:
        """Every partition of the dataset ordered by ``ordinal``; an unknown
        ``dataset_id`` is a ``Failure``."""

    def register(
        self,
        descriptor: DatasetDescriptor,
        partitions: tuple[DatasetPartition, ...],
    ) -> Result[None]:
        """Register the identity-consistent pair once; an identical content hash
        already registered is an idempotent ``Success`` and a different descriptor
        under the same hash is ``CORE.INVARIANT_VIOLATION``."""
