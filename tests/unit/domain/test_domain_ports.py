"""Stage 5 Task 1: the injected ``Clock`` and ``IdentitySource`` domain ports.

Both are structural ``typing.Protocol`` contracts and nothing more: the module
defines no implementation, reads no wall clock and draws no random value. The
doubles below are local to this test; the reusable deterministic doubles of
Stage 5 plan section 11 belong to Task 6.

Stage 7 Task 1 (Stage 7 plan sections 2.6 and 3.2) widens ``Clock`` with the
paired ``monotonic()`` reading and adds the ``CancellationToken`` port; both stay
pure structural contracts defined in ``domain``, never imported into it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol, cast, get_type_hints

import pytest
from pydantic import TypeAdapter

from crypto_lab.domain.identifiers import (
    AttemptToken,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    RunId,
)
from crypto_lab.domain.ports import CancellationToken, Clock, IdentitySource
from crypto_lab.domain.time import MonotonicInstant, require_utc

_UUID4 = "12345678-1234-4234-8234-123456789abc"
_INSTANT = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
_MONOTONIC = MonotonicInstant(12.5)
_IDENTITY_METHODS = (
    "new_experiment_id",
    "new_run_id",
    "new_invocation_id",
    "new_logical_slot_id",
    "new_attempt_token",
)


class _StoppedClock:
    """A conforming double that never consults the wall clock."""

    def __init__(self, instant: datetime) -> None:
        self._instant = instant

    def now_utc(self) -> datetime:
        return self._instant

    def monotonic(self) -> MonotonicInstant:
        return _MONOTONIC


class _NaiveClock:
    """Structurally a clock, but its value breaks the domain UTC rule."""

    def now_utc(self) -> datetime:
        return datetime(2026, 9, 6, 12, 0, 0)  # noqa: DTZ001 - deliberate probe

    def monotonic(self) -> MonotonicInstant:
        return _MONOTONIC


class _FlagToken:
    """A conforming single-threaded cancellation double: a flag that never clears."""

    def __init__(self) -> None:
        self._requested = False

    def is_cancellation_requested(self) -> bool:
        return self._requested

    def request_cancellation(self) -> None:
        self._requested = True


class _FixedIdentitySource:
    """A conforming double returning fixed, already-shaped identifiers."""

    def new_experiment_id(self) -> str:
        return f"exp_{_UUID4}"

    def new_run_id(self) -> str:
        return f"run_{_UUID4}"

    def new_invocation_id(self) -> str:
        return f"inv_{_UUID4}"

    def new_logical_slot_id(self) -> str:
        return f"slot_{_UUID4}"

    def new_attempt_token(self) -> str:
        return "t" * 32


def _public_methods(port: type) -> set[str]:
    return {
        name
        for name, value in vars(port).items()
        if not name.startswith("_") and callable(value)
    }


def test_both_ports_are_protocols_with_exactly_the_specified_members() -> None:
    for port in (Clock, IdentitySource, CancellationToken):
        # `Protocol` is a typing special form, so the container check needs an
        # `object`-typed view of the MRO to satisfy strict equality.
        assert Protocol in cast(tuple[object, ...], port.__mro__)
    assert _public_methods(Clock) == {"now_utc", "monotonic"}
    assert _public_methods(IdentitySource) == set(_IDENTITY_METHODS)
    # Stage 5 plan section 1.4 kept `monotonic` absent until Stage 7; Stage 7 plan
    # section 2.6 (Task 1) adds it as the paired process-local reading.
    assert hasattr(Clock, "monotonic")


def test_the_ports_are_runtime_checkable_structural_contracts() -> None:
    clock: Clock = _StoppedClock(_INSTANT)
    source: IdentitySource = _FixedIdentitySource()
    assert isinstance(clock, Clock)
    assert isinstance(source, IdentitySource)
    assert not isinstance(object(), Clock)
    assert not isinstance(object(), IdentitySource)
    assert not isinstance(clock, IdentitySource)
    assert not isinstance(source, Clock)


def test_a_conforming_clock_yields_the_instant_it_was_given() -> None:
    instant = _StoppedClock(_INSTANT).now_utc()
    assert instant == _INSTANT
    assert instant.tzinfo is not None
    assert instant.utcoffset() == timedelta(0)
    assert require_utc(instant) == _INSTANT
    # Conformance is structural only; the domain time rule is what rejects a
    # naive value, so a clock double cannot smuggle one into a canonical record.
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        require_utc(_NaiveClock().now_utc())


def test_the_port_return_types_are_the_domain_aliases() -> None:
    assert get_type_hints(Clock.now_utc)["return"] is datetime
    assert get_type_hints(Clock.monotonic)["return"] is MonotonicInstant
    hints: dict[str, object] = {
        name: get_type_hints(getattr(IdentitySource, name), include_extras=True)[
            "return"
        ]
        for name in _IDENTITY_METHODS
    }
    assert hints["new_experiment_id"] is ExperimentId
    assert hints["new_run_id"] is RunId
    assert hints["new_invocation_id"] is InvocationId
    assert hints["new_logical_slot_id"] is LogicalSlotId
    assert hints["new_attempt_token"] is AttemptToken


def test_a_conforming_identity_source_draws_values_the_aliases_accept() -> None:
    source = _FixedIdentitySource()
    assert TypeAdapter(ExperimentId).validate_python(source.new_experiment_id()) == (
        f"exp_{_UUID4}"
    )
    assert TypeAdapter(RunId).validate_python(source.new_run_id()) == f"run_{_UUID4}"
    assert TypeAdapter(InvocationId).validate_python(source.new_invocation_id()) == (
        f"inv_{_UUID4}"
    )
    assert (
        TypeAdapter(LogicalSlotId).validate_python(source.new_logical_slot_id())
        == f"slot_{_UUID4}"
    )
    assert TypeAdapter(AttemptToken).validate_python(source.new_attempt_token()) == (
        "t" * 32
    )


# --------------------------------------------------------------------------
# Stage 7 Task 1: the paired monotonic reading and the cancellation port
# --------------------------------------------------------------------------


def test_the_clock_port_has_exactly_now_utc_and_monotonic() -> None:
    assert _public_methods(Clock) == {"now_utc", "monotonic"}
    assert get_type_hints(Clock.monotonic)["return"] is MonotonicInstant


def test_a_conforming_clock_yields_the_monotonic_instant_it_was_given() -> None:
    clock: Clock = _StoppedClock(_INSTANT)
    reading = clock.monotonic()
    assert isinstance(reading, MonotonicInstant)
    assert reading == _MONOTONIC
    # Two readings of a stopped clock are the same instant: nothing here reads a
    # wall clock or a process clock.
    assert clock.monotonic() == reading
    assert isinstance(_NaiveClock(), Clock)


def test_the_cancellation_token_port_is_a_runtime_checkable_protocol() -> None:
    assert Protocol in cast(tuple[object, ...], CancellationToken.__mro__)
    assert _public_methods(CancellationToken) == {
        "is_cancellation_requested",
        "request_cancellation",
    }
    assert get_type_hints(CancellationToken.is_cancellation_requested)["return"] is bool
    assert get_type_hints(CancellationToken.request_cancellation)["return"] is type(
        None
    )
    token: CancellationToken = _FlagToken()
    clock: Clock = _StoppedClock(_INSTANT)
    assert isinstance(token, CancellationToken)
    assert not isinstance(object(), CancellationToken)
    assert not isinstance(clock, CancellationToken)
    assert not isinstance(token, Clock)
    assert not isinstance(token, IdentitySource)


def test_a_conforming_token_is_idempotent_and_never_clears() -> None:
    token = _FlagToken()
    assert not token.is_cancellation_requested()
    token.request_cancellation()
    token.request_cancellation()
    assert token.is_cancellation_requested()
    assert token.is_cancellation_requested()
