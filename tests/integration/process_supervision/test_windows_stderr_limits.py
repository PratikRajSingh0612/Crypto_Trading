"""Stage 7 Task 8: independent stderr budgets per command kind (plan 10).

Manifest row W-26 (scripted). Three invocations, one per kind, are each fed exactly
``max_stderr_bytes + 1`` bytes of stderr by the scripted controller through the real
supervisor and the real ``BoundedStderrCapture``: every capture is ``truncated`` with
``retained_byte_count == limit`` and exactly one ``PROCESS.STDERR_TRUNCATED`` on the
record. A describe takes its budget from the supervisor's ``describe_limits`` (the
harness limits, plan 9.4) and a validate or run from the request snapshot; a control
harness with the default budget fed the same bytes is not truncated, so the budget is
the configured limit and not a constant. Row 23 of the supervised matrix covers the real
flood.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from supervised_strategy import ProductionSupervision

from contract.harness import OfflineCommandHarness, build_harness
from contract.scenarios import STDERR_FLOOD_LIMITS
from crypto_lab.adapters.diagnostics import PROCESS_STDERR_TRUNCATED
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT, ProtocolLimits
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from doubles.supervision import ScriptedProcessController

_K = CommandKind
_KINDS = (_K.DESCRIBE, _K.VALIDATE, _K.RUN)
_CONFORMANT = "fake.conformant"


def _scripted_exit(stderr: bytes) -> ScriptedProcessController:
    scripted = ScriptedProcessController()
    scripted.stderr_chunks = [stderr]
    scripted.exit_after = 1
    return scripted


def _drive(
    root: Path, kind: CommandKind, *, limits: ProtocolLimits, fed: int, seed: str
) -> tuple[
    OfflineCommandHarness, StderrCapture, CommandInvocationState, tuple[str, ...]
]:
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1, controller=_scripted_exit(b"x" * fed)
    )
    harness = build_harness(
        root, _CONFORMANT, limits=limits, seed=seed, supervise=strategy
    )
    result = harness.drive(_CONFORMANT, kind, timeout_seconds=30)
    capture = result.command_result.stderr
    assert isinstance(capture, StderrCapture)
    invocation = result.command_result.invocation
    return (
        harness,
        capture,
        invocation.state,
        harness.codes_of(invocation.diagnostic_ids),
    )


@pytest.mark.parametrize("kind", _KINDS, ids=[kind.value.lower() for kind in _KINDS])
def test_each_kind_gets_its_own_stderr_budget_and_truncation_diagnostic(
    tmp_path: Path, kind: CommandKind
) -> None:
    limit = STDERR_FLOOD_LIMITS.max_stderr_bytes
    _harness, capture, state, codes = _drive(
        tmp_path / "bounded",
        kind,
        limits=STDERR_FLOOD_LIMITS,
        fed=limit + 1,
        seed=f"task8-stderr-{kind.value.lower()}",
    )
    assert state is CommandInvocationState.EXITED
    assert capture.truncated is True
    assert capture.retained_byte_count == limit
    assert codes.count(PROCESS_STDERR_TRUNCATED) == 1
    # The control: the same bytes under the default budget are retained whole.
    _control, whole, control_state, control_codes = _drive(
        tmp_path / "default",
        kind,
        limits=PROTOCOL_LIMITS_DEFAULT,
        fed=limit + 1,
        seed=f"task8-stderr-control-{kind.value.lower()}",
    )
    assert control_state is CommandInvocationState.EXITED
    assert PROTOCOL_LIMITS_DEFAULT.max_stderr_bytes > limit + 1
    assert whole.truncated is False
    assert whole.retained_byte_count == limit + 1
    assert PROCESS_STDERR_TRUNCATED not in control_codes
