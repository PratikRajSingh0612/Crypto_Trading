"""Stage 6 Task 8: the adapter-side verification contract of plan 3.6.

The harness writes a conformant request, then tampers the file (or the launch
argument) before launch, against ``fake.conformant``. Each vector ends with exit
``10``, no output file and no stdout byte, and the core records the run ``FAILED``
with ``SCHEMA.REQUEST_INVALID`` carrying the absence detail of the exit-``10``
cell of plan 9.1 (``manifest_present: false`` for a run, ``output_present: false``
for a validate).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import (
    CommandRun,
    OfflineCommandHarness,
    assert_token_absent,
    assert_token_only_in_wire_material,
    build_harness,
    token_free_projections,
)
from contract.scenarios import (
    ADAPTER_SIDE_VECTORS,
    DEFAULT_TIMEOUT_SECONDS,
    AdapterSideVector,
)
from crypto_lab.adapters.diagnostics import SCHEMA_REQUEST_INVALID
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import (
    ProtocolIntegrityStatus,
    ReconciliationVerdict,
)
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)

_CONFORMANT = "fake.conformant"
_IDS = tuple(vector.name for vector in ADAPTER_SIDE_VECTORS)


def _missing(value: object) -> bool:
    return value is MISSING


def _drive(
    vector: AdapterSideVector, root: Path
) -> tuple[OfflineCommandHarness, CommandRun]:
    harness = build_harness(
        root, _CONFORMANT, limits=PROTOCOL_LIMITS_DEFAULT, seed=f"task8-{vector.name}"
    )
    experiment = harness.new_experiment(_CONFORMANT)
    _experiment, run = harness.new_attempt(experiment)
    if vector.command is CommandKind.VALIDATE:
        run = harness.validating(run)
        return harness, harness.validate(
            run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS, tamper=vector.tamper
        )
    run = harness.ready(run)
    return harness, harness.run(
        run,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        tamper=vector.tamper,
        work_dir_tail=vector.work_dir_tail,
    )


def test_the_five_vectors_are_the_plan_inventory() -> None:
    assert _IDS == (
        "payload-hash-run",
        "protocol-version-run",
        "validate-envelope-to-run",
        "work-dir-tail-run",
        "payload-hash-validate",
    )
    assert [vector.command for vector in ADAPTER_SIDE_VECTORS].count(
        CommandKind.VALIDATE
    ) == 1


@pytest.mark.parametrize("vector", ADAPTER_SIDE_VECTORS, ids=_IDS)
def test_a_tampered_request_is_refused_with_exit_ten(
    vector: AdapterSideVector, tmp_path: Path
) -> None:
    harness, result = _drive(vector, tmp_path)
    invocation = result.command_result.invocation
    assert invocation.command_kind is vector.command
    assert invocation.state is CommandInvocationState.EXITED
    assert invocation.native_exit_value == 10
    # No output file, no stdout byte, no event.
    assert result.written_paths == frozenset()
    assert result.raw_stdout_lines == ()
    assert result.command_result.accepted_events == ()
    assert _missing(result.command_result.parsed_output)
    assert result.command_result.protocol_integrity is ProtocolIntegrityStatus.INTACT
    run = harness.stored_run(invocation.run_id)
    assert run.state is EngineRunState.FAILED
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    assert reconciliation.verdict is ReconciliationVerdict.FAILED
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == SCHEMA_REQUEST_INVALID
    assert primary.details[vector.absence_detail] is False
    assert primary.details["native_exit_value"] == 10
    assert run.primary_terminal_diagnostic_id == primary.diagnostic_id
    token = harness.token_for(run.run_id)
    assert_token_absent(token_free_projections(result), token)
    assert_token_only_in_wire_material(result, token)


def _rename_adapter(document: dict[str, Any]) -> None:
    """Name an adapter this fake does not serve and re-sign the payload, so the
    refusal comes from the fake's identity check and not from the payload hash."""
    payload = document["payload"]
    payload["adapter"]["adapter_name"] = "fake.unknown-adapter"
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    document["payload_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "command", [CommandKind.VALIDATE, CommandKind.RUN], ids=["validate", "run"]
)
def test_an_unknown_adapter_identity_is_refused_for_every_command(
    command: CommandKind, tmp_path: Path
) -> None:
    """The fake serves the table's names only: validate and run refuse an unknown
    adapter identity with exit ``10`` exactly as describe does, so no command falls
    back to the conformant behaviour for a misspelled or foreign name."""
    vector = AdapterSideVector(
        name="unknown-adapter", command=command, tamper=_rename_adapter
    )
    harness, result = _drive(vector, tmp_path)
    invocation = result.command_result.invocation
    assert invocation.state is CommandInvocationState.EXITED
    assert invocation.native_exit_value == 10
    assert result.written_paths == frozenset()
    assert result.raw_stdout_lines == ()
    assert harness.stored_run(invocation.run_id).state is EngineRunState.FAILED
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    primary = reconciliation.primary_diagnostic
    assert not _missing(primary)
    assert primary.error_code == SCHEMA_REQUEST_INVALID
    assert primary.details[vector.absence_detail] is False


def test_the_untampered_request_is_the_positive_control(tmp_path: Path) -> None:
    """Without tampering the same launch validates cleanly, so every exit ``10``
    above is caused by the tamper and not by the harness's request material."""
    harness = build_harness(
        tmp_path, _CONFORMANT, limits=PROTOCOL_LIMITS_DEFAULT, seed="task8-control"
    )
    experiment = harness.new_experiment(_CONFORMANT)
    _experiment, run = harness.new_attempt(experiment)
    run = harness.validating(run)
    result = harness.validate(run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS)
    assert result.command_result.invocation.native_exit_value == 0
    assert result.written_paths == frozenset({"output.json"})
    assert harness.stored_run(run.run_id).state is EngineRunState.READY
