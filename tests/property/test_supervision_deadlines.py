"""Stage 7 Task 1 properties over the paired deadline and the heartbeat monitor.

Plan Task 1 Step 1 asks for the ``hypothesis`` property that ``remaining`` is
non-negative and ``passed`` is monotone over arbitrary bounded floats. The cases
below pin that and its neighbours: ``remaining`` is zero exactly when ``passed``;
both are monotone in the observation; ``MonotonicInstant.until`` is antisymmetric
and agrees with the dataclass ordering; ``plus`` never moves an instant backwards;
and the monitor is due exactly from its last reset plus the threshold.

``deadline=None`` because hypothesis's per-example deadline flakes under host load
(the repository's documented contention mode); example counts are bounded instead.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.domain.time import MonotonicInstant
from crypto_lab.process_supervision.deadlines import HeartbeatMonitor, PairedDeadline

_INSTANT = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
#: Monotonic readings: finite, non-negative, far below any float-precision cliff.
_SECONDS = st.floats(
    min_value=0.0, max_value=1e9, allow_nan=False, allow_infinity=False
)
#: The record's `timeout_seconds` span (1..604800) doubles as the heartbeat span.
_DURATIONS = st.integers(min_value=1, max_value=604_800)


def _deadline(swap: float, timeout_seconds: int) -> PairedDeadline:
    return PairedDeadline(
        _INSTANT + timedelta(seconds=timeout_seconds),
        MonotonicInstant(swap).plus(timeout_seconds),
        timeout_seconds,
    )


@settings(max_examples=200, deadline=None)
@given(swap=_SECONDS, timeout_seconds=_DURATIONS, now=_SECONDS)
def test_remaining_is_never_negative_and_zero_exactly_when_passed(
    swap: float, timeout_seconds: int, now: float
) -> None:
    deadline = _deadline(swap, timeout_seconds)
    observed = MonotonicInstant(now)
    remaining = deadline.remaining(observed)
    assert remaining >= 0.0
    assert deadline.passed(observed) == (remaining == 0.0)
    assert deadline.passed(observed) == (observed >= deadline.deadline_monotonic)


@settings(max_examples=200, deadline=None)
@given(swap=_SECONDS, timeout_seconds=_DURATIONS, first=_SECONDS, second=_SECONDS)
def test_passed_and_remaining_are_monotone_in_the_observation(
    swap: float, timeout_seconds: int, first: float, second: float
) -> None:
    earlier, later = sorted((first, second))
    deadline = _deadline(swap, timeout_seconds)
    before = MonotonicInstant(earlier)
    after = MonotonicInstant(later)
    assert deadline.remaining(before) >= deadline.remaining(after)
    if deadline.passed(before):
        assert deadline.passed(after)
    if not deadline.passed(after):
        assert not deadline.passed(before)


@settings(max_examples=200, deadline=None)
@given(swap=_SECONDS, timeout_seconds=_DURATIONS)
def test_the_deadline_is_not_passed_at_the_swap_and_is_passed_at_itself(
    swap: float, timeout_seconds: int
) -> None:
    deadline = _deadline(swap, timeout_seconds)
    at_swap = MonotonicInstant(swap)
    assert not deadline.passed(at_swap)
    assert deadline.remaining(at_swap) > 0.0
    assert deadline.passed(deadline.deadline_monotonic)
    assert deadline.remaining(deadline.deadline_monotonic) == 0.0


@settings(max_examples=200, deadline=None)
@given(left=_SECONDS, right=_SECONDS)
def test_until_is_antisymmetric_and_agrees_with_the_ordering(
    left: float, right: float
) -> None:
    first = MonotonicInstant(left)
    second = MonotonicInstant(right)
    assert first.until(second) == -second.until(first)
    assert (first.until(second) > 0.0) == (first < second)
    assert (first.until(second) == 0.0) == (first == second)
    assert first.until(first) == 0.0


@settings(max_examples=200, deadline=None)
@given(start=_SECONDS, offset=_SECONDS)
def test_plus_never_moves_an_instant_backwards(start: float, offset: float) -> None:
    base = MonotonicInstant(start)
    moved = base.plus(offset)
    assert moved >= base
    assert base.until(moved) >= 0.0
    assert moved.until(base) <= 0.0


@settings(max_examples=200, deadline=None)
@given(
    threshold=_DURATIONS,
    armed_at=_SECONDS,
    resets=st.lists(_SECONDS, max_size=8),
    probe=_SECONDS,
)
def test_the_monitor_is_due_exactly_from_its_last_reset_plus_the_threshold(
    threshold: int, armed_at: float, resets: list[float], probe: float
) -> None:
    monitor = HeartbeatMonitor(missing_heartbeat_seconds=threshold)
    monitor.arm(MonotonicInstant(armed_at))
    last = armed_at
    # A supervisor resets with its own later readings; a reset never runs before
    # the arming instant, so earlier draws are skipped rather than applied.
    for reset_at in sorted(reset for reset in resets if reset >= armed_at):
        monitor.reset(MonotonicInstant(reset_at))
        last = reset_at
    due_at = MonotonicInstant(last).plus(threshold)
    observed = MonotonicInstant(probe)
    assert monitor.due(observed) == (observed >= due_at)
    assert monitor.remaining(observed) == max(0.0, observed.until(due_at))
    assert monitor.remaining(observed) >= 0.0
    assert monitor.minted is False
