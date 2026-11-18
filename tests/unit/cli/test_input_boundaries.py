"""Stage 10 Task 3: strict typed input boundary and dataset confinement tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from crypto_lab.domain.results import Failure, Success
from crypto_lab.experiments.application import (
    DatasetConfinementReader,
    ExplicitExperimentInput,
    register_dataset_input,
)
from crypto_lab.experiments.diagnostics import INVARIANT_VIOLATION, stage5_failure

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)


class _RefusingConfinementReader:
    def __init__(self, reason: str) -> None:
        self.reason = reason
        self.opened: list[str] = []

    def read_confined(self, relative_path: str) -> Success[bytes] | Failure:
        return stage5_failure(
            INVARIANT_VIOLATION,
            f"confinement refused: {self.reason}",
            source_component="cli.reader",
            timestamp_utc=NOW,
        )


def test_explicit_inputs_reject_unknown_fields() -> None:
    """IB: unknown, malformed, coercible financial and invalid UTC input
    refuses before mutation.
    """
    # Unknown field rejected
    with pytest.raises(ValidationError):
        ExplicitExperimentInput.model_validate(
            {
                "strategy_id": "sma_cross",
                "initial_capital_quote": Decimal("10000"),
                "observed_at_utc": NOW,
                "unknown_extra_field": "boom",
            }
        )

    # Coercible float/int rejected for Decimal financial value
    with pytest.raises(ValidationError):
        ExplicitExperimentInput.model_validate(
            {
                "strategy_id": "sma_cross",
                "initial_capital_quote": 10000.5,
                "observed_at_utc": NOW,
            }
        )

    # Naive datetime (non-UTC) rejected
    with pytest.raises(ValidationError):
        ExplicitExperimentInput.model_validate(
            {
                "strategy_id": "sma_cross",
                "initial_capital_quote": Decimal("10000"),
                "observed_at_utc": NOW.replace(tzinfo=None),
            }
        )


def test_dataset_confinement_precedes_open() -> None:
    """IB: an injected reader refusing ancestor/reparse/hard-link/swap violations
    prevents application registration.
    """
    reader = _RefusingConfinementReader("reparse_point")
    assert isinstance(reader, DatasetConfinementReader)
    res = register_dataset_input(
        relative_path="../escape/data.ndjson",
        confinement_reader=reader,
        observed_at_utc=NOW,
    )
    assert isinstance(res, Failure)
    assert reader.opened == []
