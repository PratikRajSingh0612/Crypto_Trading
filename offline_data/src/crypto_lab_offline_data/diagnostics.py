"""Refusal diagnostics of plan section 5.4 and the provider contract of R7.

Every refusal the sub-project emits is one core ``Diagnostic`` inside a core
``Failure``: severity ``ERROR``, category ``SCHEMA_VALIDATION``, source
component ``crypto-lab-offline-data``, not retriable, the error code drawn from
the closed ``RefusalCode`` set, the identifier and the instant taken from the
injected providers, and ``details`` carrying only the one-based line (``0`` for
the whole input), the rule and the length of the offending value. The
offending value itself never enters a diagnostic.

An injected provider whose value the core refuses (a malformed ``diag_``
identifier, a naive or non-UTC instant) is a fault of the caller's composition,
not of the input: no ``Diagnostic`` and therefore no ``Failure`` can be built
from it. Each provider value is validated when it is drawn, before any core
model is constructed from it and outside every handler that converts a
data-dependent core error, and a refused value raises ``ProviderContractError``.
It derives from ``RuntimeError`` so no ``ValueError`` conversion at a boundary
can swallow it, it names the provider method, and it never carries the value.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.identifiers import validate_prefixed_uuid4
from crypto_lab.domain.results import Failure
from crypto_lab.domain.time import require_utc

from crypto_lab_offline_data.providers import (
    DIAGNOSTIC_ID_PREFIX,
    Clock,
    IdProvider,
)

SOURCE_COMPONENT = "crypto-lab-offline-data"


class ProviderContractError(RuntimeError):
    """An injected provider returned a value the core refuses (reading R7).

    ``method`` names the provider method that violated its protocol
    (``diagnostic_id`` or ``now_utc`` in Task 1). The refused value is never
    carried, and the core error that refused it is not chained, so the exception
    can cross the sub-project's public boundary without exposing the value.
    """

    def __init__(self, method: str) -> None:
        super().__init__(f"provider method {method} returned a value the core refuses")
        self.method = method


class RefusalCode(StrEnum):
    """The closed set of ``error_code`` values the sub-project may emit."""

    CSV_ENCODING = "OFFLINE_DATA.CSV_ENCODING"
    CSV_HEADER = "OFFLINE_DATA.CSV_HEADER"
    CSV_ROW_SHAPE = "OFFLINE_DATA.CSV_ROW_SHAPE"
    CSV_TIMESTAMP = "OFFLINE_DATA.CSV_TIMESTAMP"
    CSV_NUMBER = "OFFLINE_DATA.CSV_NUMBER"
    SIZE_CEILING = "OFFLINE_DATA.SIZE_CEILING"
    ORDERING = "OFFLINE_DATA.ORDERING"
    TIMEFRAME_GRID = "OFFLINE_DATA.TIMEFRAME_GRID"
    PRICE_SANITY = "OFFLINE_DATA.PRICE_SANITY"
    VOLUME = "OFFLINE_DATA.VOLUME"
    EMPTY_SERIES = "OFFLINE_DATA.EMPTY_SERIES"
    OUTPUT_DIRECTORY = "OFFLINE_DATA.OUTPUT_DIRECTORY"
    INPUT_PATH = "OFFLINE_DATA.INPUT_PATH"


def refusal(
    code: RefusalCode,
    *,
    line: int,
    value_length: int,
    ids: IdProvider,
    clock: Clock,
) -> Failure:
    """Build the one-diagnostic ``Failure`` for a refused input.

    ``line`` is the one-based line of the offending value, or ``0`` when the
    whole input is refused; ``value_length`` is the length of the offending
    value in characters, or in bytes for the encoding and byte-ceiling rules.
    The message names the line and the rule only. The providers are drawn
    exactly once each and validated before the diagnostic is built; a value the
    core refuses raises ``ProviderContractError`` (reading R7).
    """
    diagnostic_id = _drawn_diagnostic_id(ids)
    timestamp_utc = _drawn_instant(clock)
    diagnostic = Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=diagnostic_id,
        severity=DiagnosticSeverity.ERROR,
        error_code=code.value,
        category=DiagnosticCategory.SCHEMA_VALIDATION,
        message=f"line {line} refused by rule {code.value}",
        source_component=SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=timestamp_utc,
        details={"line": line, "rule": code.value, "value_length": value_length},
        causal_diagnostic_ids=(),
    )
    return Failure(outcome="FAILURE", diagnostics=(diagnostic,))


def _drawn_diagnostic_id(ids: IdProvider) -> str:
    """Draw one ``diag_`` identifier and validate it against the core grammar."""
    value = ids.diagnostic_id()
    if not isinstance(value, str):
        raise ProviderContractError("diagnostic_id")
    try:
        return validate_prefixed_uuid4(value, DIAGNOSTIC_ID_PREFIX)
    except ValueError:
        raise ProviderContractError("diagnostic_id") from None


def _drawn_instant(clock: Clock) -> datetime:
    """Draw one instant and validate that it is timezone-aware UTC."""
    value = clock.now_utc()
    if not isinstance(value, datetime):
        raise ProviderContractError("now_utc")
    try:
        return require_utc(value)
    except ValueError:
        raise ProviderContractError("now_utc") from None
