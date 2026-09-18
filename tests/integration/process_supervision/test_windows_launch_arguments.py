"""Stage 7 Task 8: argument-array preservation and the fresh environment (plan 10).

Manifest rows W-09 to W-11. ``fake.argv-echo`` writes one canonical JSON line on stderr
with ``sys.orig_argv[1:]`` (the interpreter options and the script, which the
interpreter strips from ``sys.argv``), ``sys.argv[1:]``, the isolation flags, its
working directory and its environment key list, then the kind's ordinary output. The
tests
compare the echoed array element by element with ``["-I", "-B", <script>,
*argument_array(command)]`` for every kind (W-09), with a space, a quote, Unicode and
two spaces inside the path segments (W-10), and assert the planted parent sentinel and
the parent-only keys are absent from the child's environment (W-11). No test reads the
child's command line or environment block through the operating system: the child
reports what it received, and the launch specification the tee recorded is the other
side of the comparison.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from supervised_strategy import ProductionSupervision, assert_nothing_launched_survives

from contract.harness import CommandRun, OfflineCommandHarness, build_harness
from crypto_lab.adapters.commands import AdapterCommand, argument_array
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_WRITE_BOUNDARY_VIOLATION,
)
from crypto_lab.process_supervision.roots import plan_command_paths
from doubles.supervision import SUPERVISION_FAKE_PATH, supervised_catalog_entry_for

_K = CommandKind
_ECHO = "fake.argv-echo"
_KINDS = (_K.DESCRIBE, _K.VALIDATE, _K.RUN)
_PARENT_ONLY_KEYS = ("PATH", "SYSTEMROOT", "USERPROFILE")
_SENTINEL = "CRYPTO_LAB_PARENT_SENTINEL"


def _echo(result: CommandRun) -> dict[str, object]:
    capture = result.command_result.stderr
    assert isinstance(capture, StderrCapture)
    text = capture.sanitized_text
    assert isinstance(text, str)
    (line,) = [item for item in text.splitlines() if item.strip()]
    document = json.loads(line)
    assert isinstance(document, dict)
    return document


def _expected(
    harness: OfflineCommandHarness, result: CommandRun
) -> tuple[tuple[str, ...], str]:
    """The argument array the command layout fixes and the command root."""
    invocation = result.command_result.invocation
    run_id = invocation.run_id
    paths = plan_command_paths(
        str(harness.root),
        command_kind=invocation.command_kind,
        invocation_id=invocation.invocation_id,
        run_id=MISSING if not isinstance(run_id, str) else run_id,
    )
    entry = supervised_catalog_entry_for(_ECHO)
    payload: dict[str, object] = {
        "command_kind": invocation.command_kind,
        "catalog_entry": entry,
        "invocation_id": invocation.invocation_id,
        "request_path": paths.request_path,
        "timeout_seconds": invocation.timeout_seconds,
    }
    if invocation.command_kind is _K.RUN:
        payload["work_dir"] = paths.work_dir
        payload["result_path"] = paths.result_path
    else:
        payload["output_path"] = paths.output_path
    command = AdapterCommand.model_validate(payload)
    return argument_array(command), paths.command_root


def _assert_echo_matches(
    harness: OfflineCommandHarness,
    result: CommandRun,
    strategy: ProductionSupervision,
) -> None:
    invocation = result.command_result.invocation
    assert invocation.state is CommandInvocationState.EXITED
    assert invocation.native_exit_value == 0
    codes = harness.codes_of(invocation.diagnostic_ids)
    assert PROCESS_WRITE_BOUNDARY_VIOLATION not in codes
    arguments, command_root = _expected(harness, result)
    echo = _echo(result)
    assert echo["argv"] == ["-I", "-B", str(SUPERVISION_FAKE_PATH), *arguments]
    assert echo["arguments"] == list(arguments)
    assert echo["isolated"] == 1
    assert echo["dont_write_bytecode"] == 1
    cwd = echo["cwd"]
    assert isinstance(cwd, str)
    assert Path(cwd) == Path(command_root)
    (specification,) = strategy.launches
    assert specification.argv == (
        str(Path(sys.executable)),
        "-I",
        "-B",
        str(SUPERVISION_FAKE_PATH),
        *arguments,
    )
    assert specification.cwd == command_root
    assert not _missing(result.command_result.parsed_output)


def _missing(value: object) -> bool:
    return value is MISSING


def _drive(root: Path, kind: CommandKind, *, seed: str) -> None:
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness = build_harness(
            root, _ECHO, limits=PROTOCOL_LIMITS_DEFAULT, seed=seed, supervise=strategy
        )
        result = harness.drive(_ECHO, kind, timeout_seconds=30)
        _assert_echo_matches(harness, result, strategy)
    finally:
        assert_nothing_launched_survives(strategy)


# --- W-09, W-10: the argument array ---------------------------------------------------


@pytest.mark.parametrize("kind", _KINDS, ids=[kind.value.lower() for kind in _KINDS])
def test_the_fake_echoes_exactly_the_argument_array_for_every_kind(
    tmp_path: Path, kind: CommandKind
) -> None:
    _drive(tmp_path / "sup", kind, seed=f"task8-argv-{kind.value.lower()}")


def test_spaces_quotes_unicode_and_blank_looking_components_survive(
    tmp_path: Path,
) -> None:
    # Hostile content lives in the path segments the argument array carries: a space,
    # an apostrophe, Unicode and two consecutive spaces (plan 10).
    root = tmp_path / "a b" / "it's" / "ünï cøde" / "two  spaces"
    _drive(root, _K.RUN, seed="task8-argv-hostile")


# --- W-11: the fresh environment block ------------------------------------------------


def test_the_child_sees_no_parent_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_SENTINEL, "planted-by-the-parent")
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness = build_harness(
            tmp_path / "sup",
            _ECHO,
            limits=PROTOCOL_LIMITS_DEFAULT,
            seed="task8-environment",
            supervise=strategy,
        )
        result = harness.drive(_ECHO, _K.RUN, timeout_seconds=30)
        _assert_echo_matches(harness, result, strategy)
        keys = _echo(result)["environment_keys"]
        assert isinstance(keys, list)
        upper = {str(key).upper() for key in keys}
        # Two host-injected names may be present, so the assertion is on absences.
        assert _SENTINEL not in upper
        for key in _PARENT_ONLY_KEYS:
            assert key not in upper
    finally:
        assert_nothing_launched_survives(strategy)
