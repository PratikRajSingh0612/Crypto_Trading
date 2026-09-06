"""Injected clock and identity ports for the Stage 5 lifecycles.

Ambient wall-clock reads and ambient randomness are forbidden in the core, so
every recorded instant and every drawn operational identifier arrives through
one of these two protocols. Specification section 8.1 lists ``Clock`` as a
``domain`` port; ``IdentitySource`` is the Stage 5 plan's companion port (plan
section 3.3) for the prefixed UUID4 identifiers and the temporary attempt
token. Both are pure structural contracts: this module defines no
implementation, reads no clock and draws no random value. Concrete doubles are
test-resident (plan section 11) and a future composition root wires the real
ones.

``Clock.monotonic()`` and ``MonotonicInstant`` are deliberately absent (plan
section 1.4): the monotonic value governs only within one live supervisor and
is never persisted, so Stage 7 adds it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from crypto_lab.domain.identifiers import (
    AttemptToken,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    RunId,
)


@runtime_checkable
class Clock(Protocol):
    """Supply the current instant as a timezone-aware UTC ``datetime``."""

    def now_utc(self) -> datetime:
        """Return the current timezone-aware UTC instant."""


@runtime_checkable
class IdentitySource(Protocol):
    """Draw fresh operational identifiers and attempt tokens.

    Every value is already in canonical form for its identifier type. The
    attempt token is temporary sensitive correlation material: it is hashed with
    ``attempt_token_hash`` before it reaches any persisted record and is never a
    field of one.
    """

    def new_experiment_id(self) -> ExperimentId:
        """Return a fresh ``exp_`` identifier."""

    def new_run_id(self) -> RunId:
        """Return a fresh ``run_`` identifier."""

    def new_invocation_id(self) -> InvocationId:
        """Return a fresh ``inv_`` identifier."""

    def new_logical_slot_id(self) -> LogicalSlotId:
        """Return a fresh ``slot_`` identifier."""

    def new_attempt_token(self) -> AttemptToken:
        """Return a fresh raw attempt token."""
