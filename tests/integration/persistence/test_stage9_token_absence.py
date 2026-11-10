"""Stage 9 Task 8 (plan 7.1, requirement rows F24.1-2, F24.3-4, R10.2-07,
R30.1-02, R30.3-03, A33.4-02, A33.7-01, T28.3-04, A33.6-09): the raw attempt
token is absent from every durable surface after every row.

Each row drives a real fake adapter through the production supervisor over one
SQLite file, concludes it through the production composition, recovers, and then
scans every surface with the test-side exact-byte scan (``bytes.find`` over whole
files and over every cell of every table through an independent stdlib
connection -- an implementation independent of the production scanner): the
checkpointed database file, the ``-wal`` and ``-shm`` sidecars when present,
every ``*_json`` column, the logs root, the artifacts root (every registered
blob by its reference), the quarantine root, the core staging root and every
command root of the attempt, kept by ``close(keep_command_roots=True)`` across
the crash rows' reopen. The scan reports how many files or cells each surface
held, so an empty surface cannot pass for a clean one, and a scratch file
planted under ``tmp_path`` with the token is the positive control the same scan
must find.

The token is read from the flow's memory only to plant that control and to hand
the request material to the production path; it is never asserted into a record
and is a local of the test alone.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from crypto_lab.artifacts.finalizer import EVIDENCE_LEASE_SECONDS, RESULT_LEASE_SECONDS
from crypto_lab.domain.lifecycle import EngineRunState
from doubles.artifacts import CrashingProbe, FinalizationCrash
from persistence_support.artifacts import (
    FINALIZATION_TIMEOUT_SECONDS,
    FINALIZING_CONFIG,
    ClockAdvancingProbe,
    FinalizingSupervisedFlow,
    TokenScanReport,
    scan_tree_for_token,
)

_R: Final = EngineRunState
_CONFORMANT_DESCRIBE: Final = "row01-conformant-describe"
_SUCCESS_RUN: Final = "row03-conformant-run"
_CHECKSUM_MISMATCH_RUN: Final = "row36-checksum-mismatch-run"
_CRASH_POINTS: Final[tuple[tuple[str, int], ...]] = (
    ("before_prepared", 0),
    ("after_prepared", 0),
    ("after_move", 0),
    ("before_moved", 0),
    ("after_moved", 0),
    ("inside_registered", 0),
    ("after_registered", 0),
)
_LEASED_POINTS: Final = frozenset(
    {"after_prepared", "after_move", "before_moved", "after_moved", "inside_registered"}
)
_PLAIN_ROWS: Final = ("success", "failure", "cancellation", "timeout")
_ROWS: Final[tuple[str, ...]] = (
    *_PLAIN_ROWS,
    *(
        f"crash-{purpose}-{point}"
        for purpose in ("RESULT", "EVIDENCE")
        for point, _ in _CRASH_POINTS
    ),
)
#: The surfaces the scan must have covered with at least one file or cell.
_POPULATED_SURFACES: Final = (
    "database",
    "json_columns",
    "logs",
    "artifacts",
    "blobs",
    "command_roots",
)
#: The surfaces that are scanned even when they hold nothing.
_ALL_SURFACES: Final = (
    *_POPULATED_SURFACES,
    "wal",
    "shm",
    "quarantine",
    "staging",
)


def _crash_row(
    tmp_path: Path, purpose: str, point: str
) -> tuple[FinalizingSupervisedFlow, str, str]:
    """One crash cell: crash the conclusion in process, keep the command roots,
    reopen, let the lease expire when one is held, recover."""
    flow = FinalizingSupervisedFlow.open(tmp_path, config=FINALIZING_CONFIG)
    try:
        flow.describe(flow.scenario(_CONFORMANT_DESCRIBE))
        row = flow.scenario(
            _SUCCESS_RUN if purpose == "RESULT" else _CHECKSUM_MISMATCH_RUN
        )
        run = flow.prepare_run(row)
        outcome = flow.invoke(row, run)
        token = flow.raw_token(run.run_id)
        with pytest.raises(FinalizationCrash):
            flow.conclude_and_finalize(row, run, outcome, probe=CrashingProbe(point, 0))
        assert flow.assert_no_child_survives() >= 1
    finally:
        flow.close(keep_command_roots=True)
    reopened = FinalizingSupervisedFlow.reopen(tmp_path)
    try:
        if point in _LEASED_POINTS:
            reopened.recover()
            lease = (
                RESULT_LEASE_SECONDS if purpose == "RESULT" else EVIDENCE_LEASE_SECONDS
            )
            reopened.clock.advance(lease + 1)
        reports = reopened.recover()
        assert reports.artifacts.abandoned == 0
        expected = _R.SUCCEEDED if purpose == "RESULT" else _R.FAILED
        assert reopened.fresh_run(run.run_id).state is expected
    except BaseException:
        # A failed driver never leaks the open flow: closed (roots kept) first.
        reopened.close(keep_command_roots=True)
        raise
    return reopened, run.run_id, token


def _plain_row(tmp_path: Path, label: str) -> tuple[FinalizingSupervisedFlow, str, str]:
    flow = FinalizingSupervisedFlow.open(tmp_path, config=FINALIZING_CONFIG)
    try:
        flow.describe(flow.scenario(_CONFORMANT_DESCRIBE))
        row = flow.scenario(
            _CHECKSUM_MISMATCH_RUN if label == "failure" else _SUCCESS_RUN
        )
        run = flow.prepare_run(row)
        outcome = flow.invoke(row, run)
        token = flow.raw_token(run.run_id)
        probe = None
        if label == "cancellation":
            flow.cancel_run(run.run_id)
        if label == "timeout":
            probe = ClockAdvancingProbe(
                "after_moved", flow.clock, FINALIZATION_TIMEOUT_SECONDS + 1
            )
        conclusion = flow.conclude_and_finalize(row, run, outcome, probe=probe)
        assert conclusion is not None
        expected = {
            "success": _R.SUCCEEDED,
            "failure": _R.FAILED,
            "cancellation": _R.CANCELLED,
            "timeout": _R.TIMED_OUT,
        }[label]
        assert conclusion.run.state is expected
        flow.recover()
    except BaseException:
        # A failed driver never leaks the open flow: closed (roots kept) first.
        flow.close(keep_command_roots=True)
        raise
    return flow, run.run_id, token


def _assert_clean(report: TokenScanReport) -> None:
    assert report.hits == (), report
    assert set(report.surfaces) == set(_ALL_SURFACES)
    for surface in _POPULATED_SURFACES:
        assert report.surfaces[surface] >= 1, (surface, report)
    assert report.surfaces["database"] == 1


@pytest.mark.parametrize("label", _ROWS)
def test_token_absent_from_every_surface(tmp_path: Path, label: str) -> None:
    if label.startswith("crash-"):
        _, purpose, point = label.split("-", 2)
        flow, run_id, token = _crash_row(tmp_path, purpose, point)
    else:
        flow, run_id, token = _plain_row(tmp_path, label)
    try:
        assert len(token) >= 32  # token-shaped: the scan looks for these bytes
        # The positive control: the same scan over a scratch root finds a token
        # written into a file under ``tmp_path``.
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        planted = scratch / "planted.txt"
        planted.write_bytes(b"prefix " + token.encode("utf-8") + b" suffix\n")
        control = flow.scan_for_token(token, extra_roots=(scratch,))
        assert control.hits == (str(planted),)
        assert control.surfaces["extra:scratch"] == 1
        assert scan_tree_for_token(scratch, token) == (planted,)
        # Every durable surface of the row, after its recovery and before any
        # teardown or directory removal.
        _assert_clean(flow.scan_for_token(token))
        if label in _PLAIN_ROWS:
            assert flow.token_absent_everywhere(run_id)
        assert flow.quick_check() == "ok"
        assert flow.consistency_report().dangling_diagnostic_references == 0
    finally:
        flow.close(keep_command_roots=True)


def test_positive_control_scan_is_exact_bytes(tmp_path: Path) -> None:
    """The test-side scan is an exact-byte search: a token split by one byte is
    not found, the same token joined is, and an empty needle is refused."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    token = "a" * 40
    (scratch / "split.txt").write_bytes(b"a" * 20 + b"-" + b"a" * 19)
    (scratch / "joined.bin").write_bytes(bytes(range(256)) + token.encode() + b"\x00")
    assert scan_tree_for_token(scratch, token) == (scratch / "joined.bin",)
    with pytest.raises(ValueError, match="empty"):
        scan_tree_for_token(scratch, "")
