"""Stage 7 Task 8: Windows path cases through the production supervisor (plan 10).

Manifest rows W-01 to W-08. Real children of ``fake.conformant`` run under a supervision
root with spaces (W-01) and Unicode components (W-02); the venv launcher, its
``pyvenv.cfg`` and the merged fake are copied byte for byte to Unicode-and-space paths
and launched from there (W-03, with the flipped-hash and deleted-copy negative
controls); long paths are probed rather than assumed, with both arms asserting (W-04)
and the
command-root ceiling rejected on every host (W-05); a junction above the supervision
root (W-06), a junction as the supervision root itself (W-07) and a launcher reached
through a junction with its true hash (W-08) are refused before any launch. Every
pre-swap refusal is the plan's ``Failure`` (surfaced as ``SupervisionRefused``), the
record stays ``PENDING`` and the tee recorded no launch; every real launch terminates
what it started and asserts nothing is ``ALIVE_MATCHING`` in ``finally:``.
"""

from __future__ import annotations

import _winapi
import os
import sys
from pathlib import Path

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from supervised_strategy import (
    ProductionSupervision,
    SupervisionRefused,
    assert_nothing_launched_survives,
    details_of,
    ok,
)

from contract.harness import (
    FAKE_ADAPTER_PATH,
    CommandRun,
    OfflineCommandHarness,
    build_harness,
)
from crypto_lab.adapters.diagnostics import ADAPTER_UNAVAILABLE
from crypto_lab.adapters.limits import PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.manifests import AdapterResultManifest
from crypto_lab.adapters.vocabulary import ReconciliationVerdict
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.experiments.diagnostics import IMMUTABLE_INPUT_MISMATCH
from crypto_lab.process_supervision.diagnostics import PROCESS_PATH_PREFLIGHT_REJECTED
from crypto_lab.process_supervision.models import (
    COMMAND_ROOT_CEILING,
    FILE_CEILING_WITHOUT_LONG_PATHS,
)
from crypto_lab.process_supervision.roots import PathPreflight, probe_long_path_support
from doubles.experiments import INSTANT
from doubles.supervision import supervised_catalog_entry_for

_C = CommandInvocationState
_R = EngineRunState
_K = CommandKind
_CONFORMANT = "fake.conformant"
_KINDS = (_K.DESCRIBE, _K.VALIDATE, _K.RUN)
#: ``inv_`` plus a uuid4-shaped body: the command root is the root plus one separator
#: plus this many characters (plan 7.1).
_INVOCATION_ID_LENGTH = 40
_TIMEOUT = 30


def _missing(value: object) -> bool:
    return value is MISSING


def _harness(
    root: Path,
    strategy: ProductionSupervision,
    *,
    adapter_name: str = _CONFORMANT,
    seed: str,
) -> OfflineCommandHarness:
    return build_harness(
        root,
        adapter_name,
        limits=PROTOCOL_LIMITS_DEFAULT,
        seed=seed,
        supervise=strategy,
    )


def _assert_exited_with_output(
    harness: OfflineCommandHarness,
    result: CommandRun,
    kind: CommandKind,
    strategy: ProductionSupervision,
) -> None:
    invocation = result.command_result.invocation
    assert invocation.state is _C.EXITED
    assert invocation.native_exit_value == 0
    assert invocation.cleanup_complete is True
    assert not _missing(result.command_result.parsed_output)
    assert result.command_root == harness.root / invocation.invocation_id
    assert result.command_root.parent == harness.root
    if kind is _K.RUN:
        prefix = f"runs/{invocation.run_id}/work/"
        assert result.written_paths
        assert all(path.startswith(prefix) for path in result.written_paths)
        assert isinstance(result.command_result.parsed_output, AdapterResultManifest)
        assert result.reconciliation is not None
        assert result.reconciliation.verdict is (
            ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE
        )
    else:
        assert result.written_paths == frozenset({"output.json"})
    (specification,) = strategy.launches
    assert specification.cwd == str(result.command_root)


def _drive_every_kind(root: Path, *, seed: str) -> None:
    for kind in _KINDS:
        strategy = ProductionSupervision(cancellation_grace_seconds=1)
        try:
            harness = _harness(root, strategy, seed=f"{seed}-{kind.value.lower()}")
            result = harness.drive(_CONFORMANT, kind, timeout_seconds=_TIMEOUT)
            _assert_exited_with_output(harness, result, kind, strategy)
        finally:
            assert_nothing_launched_survives(strategy)


def _refused(
    harness: OfflineCommandHarness,
    strategy: ProductionSupervision,
    kind: CommandKind,
    *,
    code: str,
    reason: str,
) -> None:
    """The plan's pre-swap ``Failure``: the record stays ``PENDING``; no launch."""
    with pytest.raises(SupervisionRefused) as caught:
        harness.drive(_CONFORMANT, kind, timeout_seconds=_TIMEOUT)
    refusal = caught.value
    (diagnostic,) = refusal.failure.diagnostics
    assert diagnostic.error_code == code
    assert diagnostic.details["reason"] == reason
    assert strategy.launches == ()
    assert harness.stored_invocation(refusal.invocation_id).state is _C.PENDING


def _padded_root(tmp_path: Path, *, target_length: int) -> Path:
    padding = target_length - len(str(tmp_path)) - 1
    assert padding >= 1, "tmp_path is too long to build the bounded supervision root"
    root = tmp_path / ("p" * padding)
    root.mkdir(parents=True)
    assert len(str(root)) == target_length
    return root


def _copy_launcher_and_fake(
    directory: Path, *, launcher_name: str, script_name: str
) -> tuple[Path, Path]:
    """Plan 10: the venv launcher, the venv's ``pyvenv.cfg`` beside it and the merged
    fake, copied byte for byte."""
    directory.mkdir(parents=True, exist_ok=True)
    launcher = directory / launcher_name
    launcher.write_bytes(Path(sys.executable).read_bytes())
    configuration = Path(sys.executable).resolve().parent.parent / "pyvenv.cfg"
    assert configuration.is_file(), "the test interpreter is not a venv launcher"
    (directory / "pyvenv.cfg").write_bytes(configuration.read_bytes())
    script = directory / script_name
    script.write_bytes(FAKE_ADAPTER_PATH.read_bytes())
    return launcher, script


def _flipped(digest: str) -> str:
    first = "0" if digest[0] != "0" else "1"
    return first + digest[1:]


# --- W-01, W-02: spaces and Unicode in the supervision root -------------------------


def test_a_supervision_root_with_spaces_reaches_exited_for_every_kind(
    tmp_path: Path,
) -> None:
    _drive_every_kind(tmp_path / "sup root a", seed="task8-spaces")


def test_a_unicode_supervision_root_reaches_exited_for_every_kind(
    tmp_path: Path,
) -> None:
    _drive_every_kind(tmp_path / "ünï cøde ✓", seed="task8-unicode")


# --- W-03: Unicode and space in the executable and script paths ---------------------


def test_a_unicode_executable_and_script_path_are_launched(tmp_path: Path) -> None:
    launcher, script = _copy_launcher_and_fake(
        tmp_path / "ünï cøde",
        launcher_name="python launcher.exe",
        script_name="fake adapter.py",
    )
    entry = supervised_catalog_entry_for(
        _CONFORMANT, executable=launcher, script=script
    )
    assert entry.executable_path == str(launcher)
    for kind in _KINDS:
        strategy = ProductionSupervision(
            cancellation_grace_seconds=1, catalog_entry=entry
        )
        try:
            harness = _harness(
                tmp_path / "sup", strategy, seed=f"task8-copied-{kind.value.lower()}"
            )
            result = harness.drive(_CONFORMANT, kind, timeout_seconds=_TIMEOUT)
            _assert_exited_with_output(harness, result, kind, strategy)
            (specification,) = strategy.launches
            assert specification.argv[0] == str(launcher)
            assert specification.argv[3] == str(script)
        finally:
            assert_nothing_launched_survives(strategy)
    # Negative control 1: one hex digit of the registered hash flipped -> no launch,
    # FAILED_TO_START with CORE.IMMUTABLE_INPUT_MISMATCH, run FAILED.
    mismatched = entry.model_copy(
        update={"executable_hash": _flipped(entry.executable_hash)}
    )
    strategy = ProductionSupervision(
        cancellation_grace_seconds=1, catalog_entry=mismatched
    )
    harness = _harness(
        tmp_path / "sup-mismatch", strategy, seed="task8-copied-mismatch"
    )
    result = harness.drive(_CONFORMANT, _K.RUN, timeout_seconds=_TIMEOUT)
    invocation = result.command_result.invocation
    assert invocation.state is _C.FAILED_TO_START
    assert harness.primary_code_of(invocation) == IMMUTABLE_INPUT_MISMATCH
    assert details_of(harness, invocation, IMMUTABLE_INPUT_MISMATCH)["reason"] == (
        "hash_mismatch"
    )
    assert harness.stored_run(invocation.run_id).state is _R.FAILED
    assert strategy.launches == ()
    assert result.outcome is None
    # Negative control 2: the copy deleted -> FAILED_TO_START with ADAPTER.UNAVAILABLE,
    # run UNAVAILABLE, no launch.
    launcher.unlink()
    strategy = ProductionSupervision(cancellation_grace_seconds=1, catalog_entry=entry)
    harness = _harness(tmp_path / "sup-absent", strategy, seed="task8-copied-absent")
    result = harness.drive(_CONFORMANT, _K.RUN, timeout_seconds=_TIMEOUT)
    invocation = result.command_result.invocation
    assert invocation.state is _C.FAILED_TO_START
    assert harness.primary_code_of(invocation) == ADAPTER_UNAVAILABLE
    assert details_of(harness, invocation, ADAPTER_UNAVAILABLE)["reason"] == (
        "executable_absent"
    )
    assert harness.stored_run(invocation.run_id).state is _R.UNAVAILABLE
    assert strategy.launches == ()
    assert invocation.process_created is False


# --- W-04, W-05: long paths --------------------------------------------------------


def test_long_paths_succeed_when_supported_and_are_rejected_deterministically_otherwise(
    tmp_path: Path,
) -> None:
    # The RUN command root lands in 240..247 characters and the manifest path beyond
    # 259 (plan 10): root 203 + separator + the 40-character invocation id = 244.
    root = _padded_root(tmp_path, target_length=203)
    command_root_length = len(str(root)) + 1 + _INVOCATION_ID_LENGTH
    assert 240 <= command_root_length <= COMMAND_ROOT_CEILING
    manifest_length = command_root_length + len(
        r"\runs\run_00000000-0000-4000-8000-000000000000\work\adapter-result-manifest.json"
    )
    assert manifest_length > FILE_CEILING_WITHOUT_LONG_PATHS
    supported = ok(probe_long_path_support(str(root), now=INSTANT)).long_paths_supported
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    try:
        harness = _harness(root, strategy, seed="task8-long")
        if supported:
            result = harness.drive(_CONFORMANT, _K.RUN, timeout_seconds=_TIMEOUT)
            _assert_exited_with_output(harness, result, _K.RUN, strategy)
            assert len(str(result.command_root)) == command_root_length
            assert len(str(result.work_dir / "adapter-result-manifest.json")) > (
                FILE_CEILING_WITHOUT_LONG_PATHS
            )
        else:
            _refused(
                harness,
                strategy,
                _K.RUN,
                code=PROCESS_PATH_PREFLIGHT_REJECTED,
                reason="ceiling_exceeded",
            )
    finally:
        assert_nothing_launched_survives(strategy)


def test_a_command_root_longer_than_the_directory_ceiling_is_rejected_on_every_host(
    tmp_path: Path,
) -> None:
    # 207 + 1 + 40 = 248: over the command-root ceiling whatever the probe says.
    root = _padded_root(tmp_path, target_length=207)
    strategy = ProductionSupervision(cancellation_grace_seconds=1)
    harness = _harness(root, strategy, seed="task8-ceiling")
    _refused(
        harness,
        strategy,
        _K.DESCRIBE,
        code=PROCESS_PATH_PREFLIGHT_REJECTED,
        reason="ceiling_exceeded",
    )
    # The second case: an injected unsupported preflight and a work directory over 247
    # (root 203 -> command root 244 -> work directory 295) -> the same rejection.
    bounded_root = _padded_root(tmp_path / "b", target_length=203)
    injected = ProductionSupervision(
        cancellation_grace_seconds=1,
        preflight=PathPreflight(
            supervision_root=str(bounded_root),
            long_paths_supported=False,
            directory_ceiling=247,
            file_ceiling=259,
            probed_at_utc=INSTANT,
        ),
    )
    bounded = _harness(bounded_root, injected, seed="task8-ceiling-injected")
    _refused(
        bounded,
        injected,
        _K.RUN,
        code=PROCESS_PATH_PREFLIGHT_REJECTED,
        reason="ceiling_exceeded",
    )


# --- W-06, W-07, W-08: junctions and reparse points ---------------------------------


def test_a_supervision_root_under_a_junction_is_rejected_before_any_launch(
    tmp_path: Path,
) -> None:
    (tmp_path / "target" / "sup").mkdir(parents=True)
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        strategy = ProductionSupervision(cancellation_grace_seconds=1)
        harness = _harness(tmp_path / "link" / "sup", strategy, seed="task8-junction")
        _refused(
            harness,
            strategy,
            _K.DESCRIBE,
            code=PROCESS_PATH_PREFLIGHT_REJECTED,
            reason="ancestor_reparse_point",
        )
        # Positive control: the same target through a plain directory launches.
        control = ProductionSupervision(cancellation_grace_seconds=1)
        try:
            plain = _harness(tmp_path / "target" / "plain", control, seed="task8-plain")
            result = plain.drive(_CONFORMANT, _K.DESCRIBE, timeout_seconds=_TIMEOUT)
            _assert_exited_with_output(plain, result, _K.DESCRIBE, control)
        finally:
            assert_nothing_launched_survives(control)
    finally:
        os.rmdir(tmp_path / "link")


def test_a_junction_planted_as_the_command_root_parent_is_rejected(
    tmp_path: Path,
) -> None:
    (tmp_path / "target").mkdir()
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        strategy = ProductionSupervision(cancellation_grace_seconds=1)
        # The junction itself is the supervision root, so it is the command root's
        # parent; the probe refuses the reparse point before any record is loaded.
        harness = _harness(tmp_path / "link", strategy, seed="task8-junction-root")
        _refused(
            harness,
            strategy,
            _K.RUN,
            code=PROCESS_PATH_PREFLIGHT_REJECTED,
            reason="ancestor_reparse_point",
        )
        assert list((tmp_path / "target").iterdir()) == []
    finally:
        os.rmdir(tmp_path / "link")


def test_an_executable_path_through_a_junction_is_refused_even_with_a_matching_hash(
    tmp_path: Path,
) -> None:
    launcher, script = _copy_launcher_and_fake(
        tmp_path / "real", launcher_name="python.exe", script_name="fake_adapter.py"
    )
    _winapi.CreateJunction(str(tmp_path / "real"), str(tmp_path / "link"))
    try:
        through_junction = supervised_catalog_entry_for(
            _CONFORMANT, executable=tmp_path / "link" / "python.exe", script=script
        )
        # The hash is the true one: only the ancestor walk can refuse this launcher.
        assert through_junction.executable_hash == (
            supervised_catalog_entry_for(
                _CONFORMANT, executable=launcher, script=script
            ).executable_hash
        )
        strategy = ProductionSupervision(
            cancellation_grace_seconds=1, catalog_entry=through_junction
        )
        harness = _harness(tmp_path / "sup", strategy, seed="task8-junction-exe")
        result = harness.drive(_CONFORMANT, _K.RUN, timeout_seconds=_TIMEOUT)
        invocation = result.command_result.invocation
        assert invocation.state is _C.FAILED_TO_START
        assert harness.primary_code_of(invocation) == IMMUTABLE_INPUT_MISMATCH
        assert details_of(harness, invocation, IMMUTABLE_INPUT_MISMATCH)["reason"] == (
            "ancestor_reparse_point"
        )
        assert harness.stored_run(invocation.run_id).state is _R.FAILED
        assert strategy.launches == ()
        assert result.outcome is None
        # Positive control: the same bytes through the plain directory launch.
        control = ProductionSupervision(
            cancellation_grace_seconds=1,
            catalog_entry=supervised_catalog_entry_for(
                _CONFORMANT, executable=launcher, script=script
            ),
        )
        try:
            plain = _harness(tmp_path / "sup-plain", control, seed="task8-plain-exe")
            exited = plain.drive(_CONFORMANT, _K.RUN, timeout_seconds=_TIMEOUT)
            _assert_exited_with_output(plain, exited, _K.RUN, control)
        finally:
            assert_nothing_launched_survives(control)
    finally:
        os.rmdir(tmp_path / "link")
