"""The strategy-version registry port (Stage 8 plan reading 12).

Specification 8.2 names no port for strategy versions and specification 23.3.1
gives them a table, so the Stage 8 plan introduces ``StrategyVersionRepository``
beside the dataset port: ``get_by_hash`` reads one immutable ``StrategyVersion``
by its content identity and ``register`` stores it once. Every method is
synchronous and returns ``Result[...]``: a missing identity is a ``Failure``
carrying ``CORE.INVARIANT_VIOLATION`` (the Stage 5 port convention); an
identical hash already registered is an idempotent ``Success``; a different
record under the same hash, or a second version of one strategy at the same
``created_at_utc`` (the specification's unique ``(strategy_id, created_at_utc)``),
is ``CORE.INVARIANT_VIOLATION``. A repository never commits on its own; the
caller owns the transaction.

The module imports ``domain`` and its own package only (plan Task 3); the
concrete implementation lives in ``crypto_lab.persistence`` (Stage 8).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from crypto_lab.domain.identifiers import Sha256
from crypto_lab.domain.results import Result
from crypto_lab.strategy.versioning import StrategyVersion

__all__ = ["StrategyVersionRepository"]


@runtime_checkable
class StrategyVersionRepository(Protocol):
    """Immutable strategy versions by content identity (plan reading 12)."""

    def get_by_hash(self, content_hash: Sha256) -> Result[StrategyVersion]:
        """The version registered under ``content_hash``; absent is a ``Failure``."""

    def register(self, version: StrategyVersion) -> Result[None]:
        """Register the version once; an identical hash is an idempotent ``Success``
        and a different record under the same hash, or a second version of the
        strategy at the same instant, is ``CORE.INVARIANT_VIOLATION``."""
