"""Stage 7 Task 1: paired deadlines and the heartbeat monitor (plan 3.3, 6.1, 6.2).

``PairedDeadline`` holds the committed record's durable UTC deadline beside the
process-local monotonic deadline the supervisor derives at the ``PENDING`` to
``STARTING`` swap (spec 14.8). Only the monotonic value governs inside a live
supervisor; it is frozen, so a heartbeat can never move it. ``HeartbeatMonitor`` is
the mutable per-invocation threshold: armed at the handoff, reset on every accepted
heartbeat, due once the threshold elapses, and never a terminal cause (spec 15.3).
Every value here is pure arithmetic over injected instants; nothing reads a clock.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta, timezone

import pytest

from crypto_lab.domain.time import MonotonicInstant
from crypto_lab.process_supervision.deadlines import HeartbeatMonitor, PairedDeadline

_INSTANT = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


def _four_second_deadline() -> PairedDeadline:
    return PairedDeadline(_INSTANT + timedelta(seconds=4), MonotonicInstant(14.0), 4)


# --------------------------------------------------------------------------
# PairedDeadline
# --------------------------------------------------------------------------


def test_a_paired_deadline_reports_remaining_and_passed() -> None:
    deadline = PairedDeadline(
        _INSTANT + timedelta(seconds=4), MonotonicInstant(14.0), 4
    )
    assert deadline.remaining(MonotonicInstant(11.5)) == 2.5
    assert not deadline.passed(MonotonicInstant(13.999))
    assert deadline.passed(MonotonicInstant(14.0))


def test_remaining_is_clamped_at_zero_once_the_deadline_has_passed() -> None:
    deadline = _four_second_deadline()
    assert deadline.remaining(MonotonicInstant(14.0)) == 0.0
    assert deadline.remaining(MonotonicInstant(20.0)) == 0.0
    assert deadline.passed(MonotonicInstant(20.0))
    assert deadline.remaining(MonotonicInstant(0.0)) == 14.0
    assert not deadline.passed(MonotonicInstant(0.0))


def test_the_paired_deadline_is_the_swap_instant_plus_the_record_timeout() -> None:
    swap = MonotonicInstant(10.0)
    deadline = PairedDeadline(_INSTANT + timedelta(seconds=4), swap.plus(4), 4)
    assert deadline.deadline_utc == _INSTANT + timedelta(seconds=4)
    assert deadline.deadline_monotonic == MonotonicInstant(14.0)
    assert deadline.timeout_seconds == 4
    assert deadline.remaining(swap) == 4.0
    assert not deadline.passed(swap)


def test_the_paired_deadline_is_frozen_and_slotted_so_a_heartbeat_cannot_move_it() -> (
    None
):
    deadline = _four_second_deadline()
    with pytest.raises(FrozenInstanceError):
        deadline.deadline_monotonic = MonotonicInstant(99.0)  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        deadline.timeout_seconds = 99  # type: ignore[misc]
    assert not hasattr(deadline, "__dict__")
    assert deadline == _four_second_deadline()
    assert deadline != PairedDeadline(
        _INSTANT + timedelta(seconds=4), MonotonicInstant(15.0), 4
    )


@pytest.mark.parametrize(
    "deadline_utc",
    [
        datetime(2026, 9, 13, 12, 0, 4),  # noqa: DTZ001 - deliberate naive probe
        datetime(
            2026, 9, 13, 12, 0, 4, tzinfo=timezone(timedelta(hours=5, minutes=30))
        ),
    ],
)
def test_a_paired_deadline_requires_a_utc_deadline(deadline_utc: datetime) -> None:
    with pytest.raises(ValueError, match="UTC"):
        PairedDeadline(deadline_utc, MonotonicInstant(14.0), 4)


@pytest.mark.parametrize("timeout_seconds", [0, -1, True, 4.0, "4"])
def test_a_paired_deadline_requires_a_positive_integer_timeout(
    timeout_seconds: object,
) -> None:
    with pytest.raises(ValueError, match="timeout"):
        PairedDeadline(
            _INSTANT + timedelta(seconds=4),
            MonotonicInstant(14.0),
            timeout_seconds,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("deadline_monotonic", [14.0, 14, None])
def test_a_paired_deadline_requires_a_monotonic_instant(
    deadline_monotonic: object,
) -> None:
    with pytest.raises(ValueError, match="monotonic instant"):
        PairedDeadline(
            _INSTANT + timedelta(seconds=4),
            deadline_monotonic,  # type: ignore[arg-type]
            4,
        )


def test_the_paired_deadline_has_exactly_the_three_plan_fields_in_order() -> None:
    """Plan 3.3 field order: the UTC twin, the monotonic twin, the record timeout."""
    deadline = _four_second_deadline()
    assert tuple(field.name for field in fields(deadline)) == (
        "deadline_utc",
        "deadline_monotonic",
        "timeout_seconds",
    )
    assert not hasattr(deadline, "now_utc")
    assert not hasattr(deadline, "monotonic")
    assert not hasattr(deadline, "model_validate")


# --------------------------------------------------------------------------
# HeartbeatMonitor
# --------------------------------------------------------------------------


def test_the_heartbeat_monitor_is_due_once_the_threshold_elapses_and_resets() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    monitor.arm(MonotonicInstant(10.0))
    assert not monitor.due(MonotonicInstant(11.9))
    monitor.reset(MonotonicInstant(11.9))
    assert not monitor.due(MonotonicInstant(13.8))
    assert monitor.due(MonotonicInstant(13.9))


def test_an_unarmed_monitor_is_never_due_and_starts_unminted() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    assert not monitor.due(MonotonicInstant(0.0))
    assert not monitor.due(MonotonicInstant(1e9))
    assert monitor.minted is False


def test_reset_and_remaining_before_arm_fail_closed() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    with pytest.raises(ValueError, match="not armed"):
        monitor.reset(MonotonicInstant(1.0))
    with pytest.raises(ValueError, match="not armed"):
        monitor.remaining(MonotonicInstant(1.0))
    assert not monitor.due(MonotonicInstant(1.0))


def test_remaining_counts_down_from_the_last_reset_and_clamps_at_zero() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    monitor.arm(MonotonicInstant(10.0))
    assert monitor.remaining(MonotonicInstant(10.0)) == 2.0
    assert monitor.remaining(MonotonicInstant(11.5)) == 0.5
    assert monitor.remaining(MonotonicInstant(12.0)) == 0.0
    assert monitor.due(MonotonicInstant(12.0))
    assert monitor.remaining(MonotonicInstant(13.0)) == 0.0
    monitor.reset(MonotonicInstant(13.0))
    assert monitor.remaining(MonotonicInstant(13.0)) == 2.0
    assert not monitor.due(MonotonicInstant(14.5))
    assert monitor.due(MonotonicInstant(15.0))


def test_arming_again_replaces_the_due_instant() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    monitor.arm(MonotonicInstant(10.0))
    monitor.arm(MonotonicInstant(20.0))
    assert not monitor.due(MonotonicInstant(12.0))
    assert not monitor.due(MonotonicInstant(21.9))
    assert monitor.due(MonotonicInstant(22.0))
    # Replacement, not extension: an earlier reading pulls the due instant back,
    # so an extend-only `max(...)` implementation cannot pass this pin.
    monitor.arm(MonotonicInstant(10.0))
    assert monitor.due(MonotonicInstant(12.0))
    assert monitor.remaining(MonotonicInstant(11.0)) == 1.0
    monitor.reset(MonotonicInstant(5.0))
    assert monitor.due(MonotonicInstant(7.0))
    assert not monitor.due(MonotonicInstant(6.9))


def test_minted_is_a_once_only_flag_the_supervisor_owns_and_never_disarms() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    assert monitor.minted is False
    monitor.arm(MonotonicInstant(0.0))
    assert monitor.due(MonotonicInstant(2.0))
    monitor.minted = True
    assert monitor.minted is True
    # Minting records the once-only diagnostic; the threshold keeps reporting, and
    # the supervisor consults `minted` before minting again (plan 6.2).
    assert monitor.due(MonotonicInstant(2.0))
    assert monitor.remaining(MonotonicInstant(2.0)) == 0.0
    monitor.reset(MonotonicInstant(2.0))
    assert not monitor.due(MonotonicInstant(3.0))
    assert monitor.minted is True


def test_the_monitor_holds_only_its_threshold_due_instant_and_flag() -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=2)
    assert not hasattr(monitor, "__dict__")
    with pytest.raises(AttributeError):
        monitor.extra = 1  # type: ignore[attr-defined]


@pytest.mark.parametrize("missing_heartbeat_seconds", [0, -1, True, 2.0, "2"])
def test_the_monitor_requires_a_positive_integer_threshold(
    missing_heartbeat_seconds: object,
) -> None:
    with pytest.raises(ValueError, match="heartbeat"):
        HeartbeatMonitor(
            missing_heartbeat_seconds=missing_heartbeat_seconds,  # type: ignore[arg-type]
        )


def test_the_monitor_threshold_is_keyword_only() -> None:
    with pytest.raises(TypeError, match="positional"):
        HeartbeatMonitor(2)  # type: ignore[misc]
