from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast
from uuid import UUID

from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.financial import CanonicalDecimal
from crypto_lab.domain.identifiers import ExperimentId
from crypto_lab.domain.time import UtcDateTime


class DecimalProbe(CanonicalModel):
    value: CanonicalDecimal


class UtcProbe(CanonicalModel):
    value: UtcDateTime


@given(
    st.decimals(
        min_value=Decimal("-1000000000000"),
        max_value=Decimal("1000000000000"),
        allow_nan=False,
        allow_infinity=False,
        places=12,
    ).filter(lambda value: not (value.is_zero() and value.is_signed()))
)
def test_decimal_json_round_trip_is_canonical(value: Decimal) -> None:
    model = DecimalProbe(value=value)
    encoded = model.model_dump_json()
    payload = cast(dict[str, str], json.loads(encoded))
    assert DecimalProbe.model_validate_json(encoded) == model
    assert "e" not in payload["value"].casefold()


@given(
    st.datetimes(
        min_value=datetime(2000, 1, 1),  # noqa: DTZ001 - Hypothesis requires naive bounds
        max_value=datetime(2100, 1, 1),  # noqa: DTZ001 - Hypothesis requires naive bounds
        timezones=st.just(UTC),
    )
)
def test_utc_json_round_trip_ends_in_z(value: datetime) -> None:
    model = UtcProbe(value=value)
    encoded = model.model_dump_json()
    assert encoded.endswith('Z"}')
    assert UtcProbe.model_validate_json(encoded) == model


@given(st.uuids(version=4))
def test_generated_uuid4_accepts_only_the_matching_prefix(value: UUID) -> None:
    identifier = f"exp_{value}"
    assert TypeAdapter(ExperimentId).validate_python(identifier) == identifier


@given(
    st.dictionaries(
        st.text(min_size=1, max_size=8),
        st.integers(),
        max_size=8,
    )
)
def test_canonical_object_is_key_order_invariant(value: dict[str, int]) -> None:
    reversed_value = dict(reversed(tuple(value.items())))
    assert canonical_json_bytes(value) == canonical_json_bytes(reversed_value)
