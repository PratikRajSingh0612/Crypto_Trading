"""Injected identity and clock providers of plan section 5.4.

Every identifier (``ds_``, ``part_``, ``diag_``) and every instant the
sub-project records arrives through one of the two protocols below, so tests
inject fixed values and the content identity of a fixture stays stable across
runs and machines. ``Clock`` is the ``now_utc`` half of the core's
``crypto_lab.domain.ports.Clock``: any core clock satisfies it structurally and
the sub-project needs no monotonic reading. The two production providers are
the only places in the package that draw randomness or read the wall clock, and
each value they return is checked against the core's own grammar before it is
handed out. An injected provider is held to the same grammar when its value is
drawn: ``diagnostics`` validates every draw before a core model is built from
it, and a refused value raises ``ProviderContractError`` (plan reading R7)
rather than surfacing a core ``ValidationError`` or being converted into a
refusal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable
from uuid import uuid4

from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.time import require_utc

DATASET_ID_PREFIX = "ds_"
PARTITION_ID_PREFIX = "part_"
DIAGNOSTIC_ID_PREFIX = "diag_"


@runtime_checkable
class IdProvider(Protocol):
    """Supply the three prefixed UUID4 identifiers the sub-project records."""

    def dataset_id(self) -> str:
        """Return a ``ds_`` identifier in the core's canonical form."""

    def partition_id(self) -> str:
        """Return a ``part_`` identifier in the core's canonical form."""

    def diagnostic_id(self) -> str:
        """Return a ``diag_`` identifier in the core's canonical form."""


@runtime_checkable
class Clock(Protocol):
    """Supply the current timezone-aware UTC instant."""

    def now_utc(self) -> datetime:
        """Return the current timezone-aware UTC instant."""


class Uuid4IdProvider:
    """Mint one fresh lowercase canonical UUID4 per call behind each prefix."""

    def dataset_id(self) -> str:
        return _mint(DATASET_ID_PREFIX)

    def partition_id(self) -> str:
        return _mint(PARTITION_ID_PREFIX)

    def diagnostic_id(self) -> str:
        return _mint(DIAGNOSTIC_ID_PREFIX)


class SystemClock:
    """Read the system wall clock as a timezone-aware UTC instant."""

    def now_utc(self) -> datetime:
        return require_utc(datetime.now(UTC))


def _mint(prefix: str) -> str:
    return validate_prefixed_uuid4(f"{prefix}{uuid4()}", prefix)
