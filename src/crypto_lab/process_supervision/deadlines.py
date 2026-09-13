"""Paired deadlines and heartbeat monitoring over monotonic instants (spec 14.8, 15.3).

Both values are process-local. The supervisor reads ``clock.monotonic()``
immediately before the ``PENDING`` to ``STARTING`` swap, the Stage 5 operation
stamps the durable ``deadline_utc`` inside that swap, and the pair is held here for
the life of one supervision. Only the monotonic deadline governs inside the live
supervisor; it is never persisted or serialized to the adapter, and a heartbeat
never moves it. A restart derives the remaining interval from ``deadline_utc``
alone, so it can never extend a deadline. Nothing here reads a clock or holds a
process: every method takes the injected reading as ``now``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from crypto_lab.domain.time import MonotonicInstant, require_utc


@dataclass(frozen=True, slots=True)
class PairedDeadline:
    """The committed UTC deadline beside its process-local monotonic twin (plan 6.1).

    ``deadline_utc`` is the ``STARTING`` record's ``deadline_utc``;
    ``deadline_monotonic`` is ``monotonic_at_swap.plus(timeout_seconds)``; and
    ``timeout_seconds`` is the record's snapshotted command timeout. The monotonic
    reading precedes the UTC reading, so the monotonic deadline is never later than
    the UTC one in wall terms. The value is frozen: an accepted heartbeat cannot
    extend it.
    """

    deadline_utc: datetime
    deadline_monotonic: MonotonicInstant
    timeout_seconds: int

    def __post_init__(self) -> None:
        require_utc(self.deadline_utc)
        if not isinstance(self.deadline_monotonic, MonotonicInstant):
            raise ValueError("a paired deadline needs a monotonic instant")
        if type(self.timeout_seconds) is not int or self.timeout_seconds < 1:
            raise ValueError(
                "a paired deadline timeout is a positive integer of seconds"
            )

    def remaining(self, now: MonotonicInstant) -> float:
        """Return the seconds until the monotonic deadline, zero once it has passed."""
        return max(0.0, now.until(self.deadline_monotonic))

    def passed(self, now: MonotonicInstant) -> bool:
        """Return whether ``now`` has reached the monotonic deadline (inclusive)."""
        return now >= self.deadline_monotonic


class HeartbeatMonitor:
    """The per-invocation missing-heartbeat threshold (spec 15.3, plan 6.2).

    Mutable and single-owner: the supervisor arms it with the reading taken right
    after ``record_process_start`` commits, resets it on every accepted
    ``HEARTBEAT`` and checks ``due`` each tick. A due monitor never terminates
    anything: the supervisor mints ``PROCESS.MISSING_HEARTBEAT`` exactly once and
    records that through ``minted``, which minting never disarms. ``reset`` and
    ``remaining`` before ``arm`` are a sequencing defect and fail closed; ``due``
    on an unarmed monitor is ``False``; arming again replaces the due instant.
    """

    __slots__ = ("_due_at", "_missing_heartbeat_seconds", "minted")

    minted: bool

    def __init__(self, *, missing_heartbeat_seconds: int) -> None:
        if type(missing_heartbeat_seconds) is not int or missing_heartbeat_seconds < 1:
            raise ValueError("a heartbeat threshold is a positive integer of seconds")
        self._missing_heartbeat_seconds = missing_heartbeat_seconds
        self._due_at: MonotonicInstant | None = None
        self.minted = False

    def arm(self, now: MonotonicInstant) -> None:
        """Start the threshold from ``now`` (the handoff reading)."""
        self._due_at = now.plus(self._missing_heartbeat_seconds)

    def reset(self, now: MonotonicInstant) -> None:
        """Restart the threshold from ``now`` on an accepted ``HEARTBEAT``."""
        if self._due_at is None:
            raise ValueError("the heartbeat monitor is not armed")
        self._due_at = now.plus(self._missing_heartbeat_seconds)

    def due(self, now: MonotonicInstant) -> bool:
        """Return whether the monitor is armed and ``now`` reached the due instant."""
        return self._due_at is not None and now >= self._due_at

    def remaining(self, now: MonotonicInstant) -> float:
        """Return the seconds until the due instant, zero once it has passed."""
        if self._due_at is None:
            raise ValueError("the heartbeat monitor is not armed")
        return max(0.0, now.until(self._due_at))
