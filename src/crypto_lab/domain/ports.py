"""Injected clock, identity and cancellation ports for the lifecycles.

Ambient wall-clock reads and ambient randomness are forbidden in the core, so
every recorded instant and every drawn operational identifier arrives through
one of these protocols. Specification section 8.1 lists ``Clock`` as a
``domain`` port; ``IdentitySource`` is the Stage 5 plan's companion port (plan
section 3.3) for the prefixed UUID4 identifiers and the temporary attempt
token. All are pure structural contracts: this module defines no
implementation, reads no clock, draws no random value and starts no thread.
Concrete doubles are test-resident and a future composition root wires the
real ones.

Stage 7 Task 1 (Stage 7 plan sections 2.3 and 3.2) adds the paired
``Clock.monotonic()`` reading, whose ``MonotonicInstant`` value governs only
within one live supervisor and is never persisted, and the
``CancellationToken`` port that specification section 8.2 hands to
``ProcessSupervisor.invoke`` and, later, to ``ArtifactFinalizer.finalize``.
Its thread-safe implementation lives under ``process_supervision``.
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
from crypto_lab.domain.time import MonotonicInstant


@runtime_checkable
class Clock(Protocol):
    """Supply the current UTC instant and its process-local monotonic pair."""

    def now_utc(self) -> datetime:
        """Return the current timezone-aware UTC instant."""

    def monotonic(self) -> MonotonicInstant:
        """Return the process-local monotonic reading paired with ``now_utc``.

        Spec 8.2 and 14.8: the supervisor reads it immediately before the UTC
        instant of the ``PENDING`` to ``STARTING`` swap; the value is never
        persisted or compared across restarts.
        """


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


@runtime_checkable
class CancellationToken(Protocol):
    """Spec 8.2, 14.8: an explicit, idempotent cancellation request.

    A request is observed by the supervisor at its next tick and never clears;
    a second request is a no-op. Cancellation is a token and a result category,
    never an unstructured task exception.
    """

    def is_cancellation_requested(self) -> bool:
        """Return whether cancellation has been requested."""

    def request_cancellation(self) -> None:
        """Record the cancellation request; idempotent."""
