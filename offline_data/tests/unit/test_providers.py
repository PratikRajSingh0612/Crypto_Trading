"""Identity and clock providers of plan section 5.4 and reading R7.

Injected providers are the only source of identifiers and instants in the
sub-project, so the tests prove three things: a diagnostic built through
``refusal`` carries exactly the injected identifier and instant, the
production providers mint values the core's own grammar accepts, and a
provider whose value the core refuses is a fault of the caller's composition
raised as ``ProviderContractError`` from the Task 1 public boundaries
(``refusal`` and ``read_ohlcv_csv``), never a core ``ValidationError`` escaping
and never a refusal. The exception names the provider method and never
carries the value.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.results import Success
from crypto_lab.domain.time import require_utc
from pydantic import ValidationError

from crypto_lab_offline_data.candle_csv import read_ohlcv_csv
from crypto_lab_offline_data.diagnostics import (
    ProviderContractError,
    RefusalCode,
    refusal,
)
from crypto_lab_offline_data.providers import (
    DATASET_ID_PREFIX,
    DIAGNOSTIC_ID_PREFIX,
    PARTITION_ID_PREFIX,
    Clock,
    IdProvider,
    SystemClock,
    Uuid4IdProvider,
)

OTHER_DIAGNOSTIC_ID = "diag_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"
OTHER_INSTANT = datetime(2031, 12, 31, 23, 59, 59, tzinfo=UTC)
MALFORMED_DIAGNOSTIC_ID = "diag_not-a-canonical-uuid4"
NAIVE_INSTANT = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001
OFFSET_INSTANT = datetime(
    2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=5, minutes=30))
)
ZERO_OFFSET_INSTANT = datetime(
    2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(0), "zero-offset")
)


class _OtherIds:
    """A second ``IdProvider`` double with distinct values."""

    def dataset_id(self) -> str:
        return "ds_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"

    def partition_id(self) -> str:
        return "part_8b2d4f6a-1c3e-4a5b-b7d9-0e2f4a6c8b1d"

    def diagnostic_id(self) -> str:
        return OTHER_DIAGNOSTIC_ID


class _OtherClock:
    """A second ``Clock`` double with a distinct instant."""

    def now_utc(self) -> datetime:
        return OTHER_INSTANT


class _ValueIds(_OtherIds):
    """An ``IdProvider`` whose ``diagnostic_id`` hands back one configured value."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def diagnostic_id(self) -> Any:
        return self._value


class _ValueClock:
    """A ``Clock`` that hands back one configured value."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def now_utc(self) -> Any:
        return self._value


class _CountingIds(_OtherIds):
    """An ``IdProvider`` that counts the draws of each method."""

    def __init__(self) -> None:
        self.calls = {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}

    def dataset_id(self) -> str:
        self.calls["dataset_id"] += 1
        return super().dataset_id()

    def partition_id(self) -> str:
        self.calls["partition_id"] += 1
        return super().partition_id()

    def diagnostic_id(self) -> str:
        self.calls["diagnostic_id"] += 1
        return super().diagnostic_id()


class _CountingClock(_OtherClock):
    """A ``Clock`` that counts its draws."""

    def __init__(self) -> None:
        self.calls = 0

    def now_utc(self) -> datetime:
        self.calls += 1
        return super().now_utc()


def test_refusal_uses_the_injected_identifier_and_clock(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    """The diagnostic carries exactly the injected id and instant, per double."""
    fixed = refusal(
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=0,
        ids=fixed_ids,
        clock=fixed_clock,
    )
    other = refusal(
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=0,
        ids=_OtherIds(),
        clock=_OtherClock(),
    )

    assert fixed.diagnostics[0].diagnostic_id == fixed_ids.diagnostic_id()
    assert fixed.diagnostics[0].timestamp_utc == fixed_clock.now_utc()
    assert other.diagnostics[0].diagnostic_id == OTHER_DIAGNOSTIC_ID
    assert other.diagnostics[0].timestamp_utc == OTHER_INSTANT
    assert fixed.diagnostics[0].diagnostic_id != other.diagnostics[0].diagnostic_id
    assert fixed.diagnostics[0].timestamp_utc != other.diagnostics[0].timestamp_utc


def test_refusal_draws_each_provider_value_exactly_once() -> None:
    """One refusal draws one diagnostic id and one instant, nothing else."""
    ids = _CountingIds()
    clock = _CountingClock()

    refusal(RefusalCode.CSV_HEADER, line=1, value_length=0, ids=ids, clock=clock)

    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 1}
    assert clock.calls == 1


def test_provider_contract_error_is_a_runtime_error_outside_every_conversion() -> None:
    """R7: rooted in ``RuntimeError`` so no boundary conversion can swallow it."""
    assert issubclass(ProviderContractError, RuntimeError)
    assert not issubclass(ProviderContractError, ValueError)
    assert not issubclass(ProviderContractError, ValidationError)
    assert not issubclass(ProviderContractError, OSError)


@pytest.mark.parametrize(
    "value",
    [
        MALFORMED_DIAGNOSTIC_ID,
        "ds_3c9e1b7d-5f2a-4b8c-a6d4-9e1f3b5d7c2a",
        "diag_3C9E1B7D-5F2A-4B8C-A6D4-9E1F3B5D7C2A",
        "diag_6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "",
        None,
        b"diag_3c9e1b7d-5f2a-4b8c-a6d4-9e1f3b5d7c2a",
    ],
)
def test_refusal_raises_the_contract_error_for_a_refused_diagnostic_id(
    value: Any,
    fixed_clock: Clock,
) -> None:
    """A malformed, wrongly prefixed, non-canonical or non-string id is a fault."""
    with pytest.raises(RuntimeError) as info:
        refusal(
            RefusalCode.CSV_HEADER,
            line=1,
            value_length=0,
            ids=_ValueIds(value),
            clock=fixed_clock,
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert not isinstance(error, ValidationError)
    assert error.method == "diagnostic_id"
    assert "diagnostic_id" in str(error)
    assert error.__cause__ is None
    if isinstance(value, str) and value:
        assert value not in str(error)
        assert value not in repr(error.args)
    assert repr(value) not in str(error)


@pytest.mark.parametrize(
    "value",
    [NAIVE_INSTANT, OFFSET_INSTANT, "2026-01-02T03:04:05Z", None],
)
def test_refusal_raises_the_contract_error_for_a_refused_instant(
    value: Any,
    fixed_ids: IdProvider,
) -> None:
    """A naive, non-UTC or non-datetime instant is a fault, never a refusal."""
    with pytest.raises(RuntimeError) as info:
        refusal(
            RefusalCode.CSV_HEADER,
            line=1,
            value_length=0,
            ids=fixed_ids,
            clock=_ValueClock(value),
        )

    error = info.value
    assert type(error) is ProviderContractError
    assert not isinstance(error, ValidationError)
    assert error.method == "now_utc"
    assert "now_utc" in str(error)
    assert error.__cause__ is None
    assert str(value) not in str(error)
    assert repr(value) not in str(error)


def test_a_zero_offset_instant_is_accepted_as_utc(fixed_ids: IdProvider) -> None:
    """The rule is the offset, not the tzinfo object: zero offset is UTC."""
    result = refusal(
        RefusalCode.CSV_HEADER,
        line=1,
        value_length=0,
        ids=fixed_ids,
        clock=_ValueClock(ZERO_OFFSET_INSTANT),
    )

    assert result.diagnostics[0].timestamp_utc == ZERO_OFFSET_INSTANT
    assert result.diagnostics[0].timestamp_utc.utcoffset() == timedelta(0)


def test_read_ohlcv_csv_raises_the_contract_error_for_a_malformed_id(
    invalid_root: Path,
    fixed_clock: Clock,
) -> None:
    with pytest.raises(RuntimeError) as info:
        read_ohlcv_csv(
            invalid_root / "header-only.csv",
            ids=_ValueIds(MALFORMED_DIAGNOSTIC_ID),
            clock=fixed_clock,
        )

    assert type(info.value) is ProviderContractError
    assert info.value.method == "diagnostic_id"
    assert MALFORMED_DIAGNOSTIC_ID not in str(info.value)


def test_read_ohlcv_csv_raises_the_contract_error_for_a_naive_instant(
    invalid_root: Path,
    fixed_ids: IdProvider,
) -> None:
    with pytest.raises(RuntimeError) as info:
        read_ohlcv_csv(
            invalid_root / "header-only.csv",
            ids=fixed_ids,
            clock=_ValueClock(NAIVE_INSTANT),
        )

    assert type(info.value) is ProviderContractError
    assert info.value.method == "now_utc"


def test_read_ohlcv_csv_raises_the_contract_error_for_an_absent_input_too(
    tmp_path: Path,
    fixed_clock: Clock,
) -> None:
    """The input-path refusal draws the providers like every other refusal."""
    absent = tmp_path / "absent.csv"

    with pytest.raises(RuntimeError) as info:
        read_ohlcv_csv(
            absent, ids=_ValueIds(MALFORMED_DIAGNOSTIC_ID), clock=fixed_clock
        )

    assert type(info.value) is ProviderContractError
    assert info.value.method == "diagnostic_id"
    assert not absent.exists()


def test_read_ohlcv_csv_draws_no_provider_value_when_it_accepts_the_input(
    clean_fixture: Path,
) -> None:
    """Faulty providers are never drawn on the success path, so it succeeds."""
    ids = _CountingIds()
    clock = _CountingClock()

    counted = read_ohlcv_csv(clean_fixture, ids=ids, clock=clock)
    faulty = read_ohlcv_csv(
        clean_fixture,
        ids=_ValueIds(MALFORMED_DIAGNOSTIC_ID),
        clock=_ValueClock(NAIVE_INSTANT),
    )

    assert isinstance(counted, Success)
    assert isinstance(faulty, Success)
    assert ids.calls == {"dataset_id": 0, "partition_id": 0, "diagnostic_id": 0}
    assert clock.calls == 0


@pytest.mark.parametrize(
    ("method", "prefix"),
    [
        ("dataset_id", DATASET_ID_PREFIX),
        ("partition_id", PARTITION_ID_PREFIX),
        ("diagnostic_id", DIAGNOSTIC_ID_PREFIX),
    ],
)
def test_production_identifiers_satisfy_the_core_prefix_grammar(
    method: str,
    prefix: str,
) -> None:
    """Each minted id is a lowercase canonical UUID4 behind its exact prefix."""
    provider = Uuid4IdProvider()
    mint = getattr(provider, method)

    first = mint()
    second = mint()

    assert validate_prefixed_uuid4(first, prefix) == first
    assert validate_prefixed_uuid4(second, prefix) == second
    assert first != second


def test_the_three_prefixes_are_the_core_dataset_prefixes() -> None:
    assert (DATASET_ID_PREFIX, PARTITION_ID_PREFIX, DIAGNOSTIC_ID_PREFIX) == (
        "ds_",
        "part_",
        "diag_",
    )


def test_the_system_clock_returns_a_timezone_aware_utc_instant() -> None:
    before = datetime.now(UTC)
    observed = SystemClock().now_utc()
    after = datetime.now(UTC)

    assert observed.tzinfo is not None
    assert observed.utcoffset() == timedelta(0)
    assert require_utc(observed) == observed
    assert before <= observed <= after


def test_the_production_providers_satisfy_the_protocols(
    fixed_ids: IdProvider,
    fixed_clock: Clock,
) -> None:
    assert isinstance(Uuid4IdProvider(), IdProvider)
    assert isinstance(SystemClock(), Clock)
    assert isinstance(fixed_ids, IdProvider)
    assert isinstance(fixed_clock, Clock)
