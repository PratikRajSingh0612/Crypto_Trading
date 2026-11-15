"""Explicit pytest root of the ``offline_data`` sub-project and its shared fixtures.

This file marks ``offline_data/tests`` as the sub-project's own test root so
pytest resolves this tree independently of the core repository's ``tests``
tree. Task 1 adds the shared fixtures: the fixture directories under
``tests/fixtures/candles`` and the fixed identity and clock doubles of plan
section 5.4, so every diagnostic a test provokes is deterministic. The doubles
import no production module: they satisfy the ``IdProvider`` and ``Clock``
protocols structurally, which keeps this root importable before the production
modules exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

FIXED_DATASET_ID = "ds_0f8c2a4e-6b3d-4f1a-9c7e-2d5b8a1f3c6e"
FIXED_PARTITION_ID = "part_7a1d3e5f-9b2c-4d6e-8f1a-3c5e7b9d1f2a"
FIXED_DIAGNOSTIC_ID = "diag_3c9e1b7d-5f2a-4b8c-a6d4-9e1f3b5d7c2a"
FIXED_INSTANT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class FixedIds:
    """An ``IdProvider`` double that returns the same three identifiers."""

    dataset: str = FIXED_DATASET_ID
    partition: str = FIXED_PARTITION_ID
    diagnostic: str = FIXED_DIAGNOSTIC_ID

    def dataset_id(self) -> str:
        return self.dataset

    def partition_id(self) -> str:
        return self.partition

    def diagnostic_id(self) -> str:
        return self.diagnostic


@dataclass(frozen=True, slots=True)
class FixedClock:
    """A ``Clock`` double that returns one fixed timezone-aware UTC instant."""

    instant: datetime = FIXED_INSTANT

    def now_utc(self) -> datetime:
        return self.instant


@pytest.fixture
def fixed_ids() -> FixedIds:
    """Return the deterministic identity provider double."""
    return FixedIds()


@pytest.fixture
def fixed_clock() -> FixedClock:
    """Return the deterministic clock double."""
    return FixedClock()


@pytest.fixture
def sub_project_root() -> Path:
    """Return the checked-out ``offline_data`` sub-project root."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def candles_root() -> Path:
    """Return the committed candle fixture directory."""
    return Path(__file__).resolve().parent / "fixtures" / "candles"


@pytest.fixture
def clean_fixture(candles_root: Path) -> Path:
    """Return the sixty-bar clean ``ohlcv-csv/1`` fixture."""
    return candles_root / "btcusdt-1m-clean.valid.csv"


@pytest.fixture
def invalid_root(candles_root: Path) -> Path:
    """Return the directory of refused ``ohlcv-csv/1`` fixtures."""
    return candles_root / "invalid"
