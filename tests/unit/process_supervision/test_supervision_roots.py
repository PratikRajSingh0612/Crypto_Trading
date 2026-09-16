"""Stage 7 Task 3: command roots, path preflight and bounded output reads (plan 7).

``plan_command_paths`` is the single layout authority (plan 7.1, reading 11);
``probe_long_path_support`` and ``preflight_command_paths`` refuse a root or a command
path before anything is written (plan 7.2, reading 20;
``PROCESS.PATH_PREFLIGHT_REJECTED`` as a ``Failure``); ``create_command_root`` and
``write_request_file`` are the exclusive
creates of plan 7.3; ``snapshot_written_paths`` is the write-boundary walk that never
descends through a reparse point; ``read_output_file`` reads at most ceiling + 1 bytes
and returns the plan 7.4 ``OutputReadFailure`` for a file that exists but cannot be
read; ``remove_command_root`` is the idempotent, never-raising removal of plan 7.5;
``observe_executable`` is the pre-swap executable observation of plan 4.1 row 1. The
Windows-semantics cases (junctions, sharing violations, ceilings) run on the real
filesystem under ``tmp_path``; no child process is launched anywhere here.
"""

from __future__ import annotations

import _winapi
import ast
import inspect
import os
from pathlib import Path
from typing import Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.limits import RESULT_MANIFEST_RELATIVE_PATH
from crypto_lab.domain.experiment import EngineIdentity
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import CommandKind
from crypto_lab.domain.results import Failure, Success
from crypto_lab.process_supervision import roots as roots_module
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_PATH_PREFLIGHT_REJECTED,
)
from crypto_lab.process_supervision.models import (
    COMMAND_ROOT_CEILING,
    DIRECTORY_CEILING_WITHOUT_LONG_PATHS,
    FILE_CEILING_WITHOUT_LONG_PATHS,
    LONG_PATH_CEILING,
    CleanupAction,
    CleanupFailure,
    CleanupReport,
    ExecutableObservation,
    OutputReadFailure,
)
from crypto_lab.process_supervision.roots import (
    CommandPaths,
    PathPreflight,
    create_command_root,
    observe_executable,
    plan_command_paths,
    preflight_command_paths,
    probe_long_path_support,
    read_output_file,
    remove_command_root,
    snapshot_written_paths,
    write_request_file,
)
from doubles.experiments import EXPERIMENT_ID, INSTANT, INVOCATION_ID, RUN_ID

INV: Final = INVOCATION_ID
RUN: Final = RUN_ID
EXP: Final = EXPERIMENT_ID
_INSTANT: Final = INSTANT
_SUPERVISOR: Final = "process_supervision.supervisor"
_FAKE_ENGINE: Final = EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")
#: Plan 2.6: the import closure of ``roots.py`` (``pathlib`` and ``hashlib`` are merged
#: roots; ``contextlib`` and ``datetime`` are merged roots too).
_PURE_ROOTS: Final = frozenset(
    {
        "__future__",
        "contextlib",
        "datetime",
        "hashlib",
        "pathlib",
        "typing",
        "pydantic",
        "crypto_lab",
    }
)
_DENIED_ROOTS: Final = frozenset(
    {
        "os",
        "shutil",
        "tempfile",
        "stat",
        "io",
        "sys",
        "time",
        "subprocess",
        "threading",
        "queue",
        "asyncio",
        "ctypes",
        "glob",
    }
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader"}
)
_EXPORTED: Final = [
    "CommandPaths",
    "PathPreflight",
    "create_command_root",
    "observe_executable",
    "plan_command_paths",
    "preflight_command_paths",
    "probe_long_path_support",
    "read_output_file",
    "remove_command_root",
    "snapshot_written_paths",
    "write_request_file",
]


# --------------------------------------------------------------------------
# Module-local helpers (plan Task 3 "Test helpers", one clause each)
# --------------------------------------------------------------------------


def codes_of(result: object) -> tuple[str, ...]:
    assert isinstance(result, Failure), result
    return tuple(diagnostic.error_code for diagnostic in result.diagnostics)


def ok[T](result: Success[T] | Failure) -> T:
    assert isinstance(result, Success), result
    return result.value


def run_paths(root: str) -> CommandPaths:
    return plan_command_paths(
        root, command_kind=CommandKind.RUN, invocation_id=INV, run_id=RUN
    )


def probe_or_preflight(path: str) -> Success[None] | Failure:
    probed = probe_long_path_support(path, now=_INSTANT)
    if isinstance(probed, Failure):
        return probed
    return preflight_command_paths(
        run_paths(path),
        probed.value,
        now=_INSTANT,
        invocation_id=INV,
        run_id=RUN,
        experiment_id=EXP,
    )


def _missing(value: object) -> bool:
    return value is MISSING


def _entry(path: Path, expected_hash: str) -> AdapterCatalogEntry:
    return AdapterCatalogEntry(
        adapter_name="fake.observed",
        adapter_version="1.0.0",
        engine=_FAKE_ENGINE,
        executable_path=str(path),
        executable_hash=expected_hash,
        runtime_metadata={},
    )


def _hold_open_without_sharing(path: Path) -> int:
    """Open ``path`` with share mode 0, so any other open is a sharing violation."""
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        0,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


def _module_source() -> str:
    source = roots_module.__file__
    assert source is not None
    return Path(source).read_text(encoding="utf-8")


def _imported(tree: ast.Module) -> tuple[set[str], set[str]]:
    roots: set[str] = set()
    project: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.partition(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab"):
                project.add(node.module)
    return roots, project


# --------------------------------------------------------------------------
# Plan Task 3 Step 1 (verbatim)
# --------------------------------------------------------------------------


def test_the_layout_is_the_harness_layout(tmp_path: Path) -> None:
    paths = plan_command_paths(
        str(tmp_path), command_kind=CommandKind.RUN, invocation_id=INV, run_id=RUN
    )
    assert paths.command_root == str(tmp_path / INV)
    assert paths.work_dir == str(tmp_path / INV / "runs" / RUN / "work")
    assert paths.result_path == str(
        tmp_path / INV / "runs" / RUN / "work" / "adapter-result-manifest.json"
    )
    with pytest.raises(ValueError, match="run_id"):
        plan_command_paths(
            str(tmp_path),
            command_kind=CommandKind.VALIDATE,
            invocation_id=INV,
            run_id=MISSING,
        )


def test_preflight_uses_the_directory_and_file_ceilings(tmp_path: Path) -> None:
    unsupported = PathPreflight(
        supervision_root=str(tmp_path),
        long_paths_supported=False,
        directory_ceiling=247,
        file_ceiling=259,
        probed_at_utc=_INSTANT,
    )
    supported = PathPreflight(
        supervision_root=str(tmp_path),
        long_paths_supported=True,
        directory_ceiling=1024,
        file_ceiling=1024,
        probed_at_utc=_INSTANT,
    )
    with pytest.raises(ValidationError):
        PathPreflight(
            supervision_root=str(tmp_path),
            long_paths_supported=True,
            directory_ceiling=32767,
            file_ceiling=32767,
            probed_at_utc=_INSTANT,
        )
    assert (
        preflight_command_paths(
            run_paths(str(tmp_path)),
            supported,
            now=_INSTANT,
            invocation_id=INV,
            run_id=RUN,
            experiment_id=EXP,
        ).outcome
        == "SUCCESS"
    )
    long_root = str(tmp_path / ("a" * (248 - len(str(tmp_path)) - 1)))
    failure = preflight_command_paths(
        run_paths(long_root),
        unsupported,
        now=_INSTANT,
        invocation_id=INV,
        run_id=RUN,
        experiment_id=EXP,
    )
    # PT018: the plan's `and` assertion split; the isinstance narrows Result[None]
    assert isinstance(failure, Failure)
    assert codes_of(failure) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    assert failure.diagnostics[0].details["reason"] == "ceiling_exceeded"
    assert (failure.diagnostics[0].invocation_id, failure.diagnostics[0].run_id) == (
        INV,
        RUN,
    )  # the 4.4 rejection is correlated


def test_an_ancestor_junction_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "target" / "sup").mkdir(
        parents=True
    )  # CreateJunction needs an existing directory
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        failure = probe_or_preflight(
            str(tmp_path / "link" / "sup")
        )  # exists through the junction, so the reason is the reparse point
        assert isinstance(failure, Failure)  # PT018: the plan's `and` split
        assert codes_of(failure) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
        assert failure.diagnostics[0].details["reason"] == "ancestor_reparse_point"
    finally:
        os.rmdir(tmp_path / "link")


def test_read_output_file_reads_at_most_ceiling_plus_one_bytes(tmp_path: Path) -> None:
    (tmp_path / "output.json").write_bytes(b"x" * 100)
    data = read_output_file(str(tmp_path / "output.json"), ceiling=10)
    # narrows bytes | OutputReadFailure | MISSING (plan 7.4; the carried review note);
    # PT018: the plan's `and` assertion split with both clauses kept
    assert isinstance(data, bytes)
    assert len(data) == 11


def test_remove_command_root_reports_a_sharing_violation_and_is_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "inv"
    root.mkdir()
    (root / "request.json").write_bytes(b"{}")
    with (root / "request.json").open("rb"):
        report = remove_command_root(str(root))
    assert report.failures[0].action is CleanupAction.COMMAND_ROOT_REMOVED
    # PT018: the plan's `and` assertion split; both removals still run in order
    assert remove_command_root(str(root)).complete
    assert remove_command_root(str(root)).complete


# --------------------------------------------------------------------------
# The layout (plan 7.1)
# --------------------------------------------------------------------------


def test_describe_and_validate_layouts_have_an_output_file_and_no_work_dir(
    tmp_path: Path,
) -> None:
    describe = plan_command_paths(
        str(tmp_path), command_kind=CommandKind.DESCRIBE, invocation_id=INV
    )
    assert describe.command_root == str(tmp_path / INV)
    assert describe.request_path == str(tmp_path / INV / "request.json")
    assert describe.output_path == str(tmp_path / INV / "output.json")
    assert _missing(describe.work_dir)
    assert _missing(describe.result_path)
    validate = plan_command_paths(
        str(tmp_path), command_kind=CommandKind.VALIDATE, invocation_id=INV, run_id=RUN
    )
    # a VALIDATE requires the run id but uses it in no path (plan 7.1)
    assert validate == describe
    with pytest.raises(ValueError, match="run_id"):
        plan_command_paths(
            str(tmp_path),
            command_kind=CommandKind.DESCRIBE,
            invocation_id=INV,
            run_id=RUN,
        )
    with pytest.raises(ValueError, match="run_id"):
        plan_command_paths(
            str(tmp_path), command_kind=CommandKind.RUN, invocation_id=INV
        )
    run = run_paths(str(tmp_path))
    assert _missing(run.output_path)
    assert run.request_path == str(tmp_path / INV / "request.json")
    assert run.directories == (run.command_root, run.work_dir)
    assert run.files == (run.request_path, run.result_path)
    assert describe.directories == (describe.command_root,)
    assert describe.files == (describe.request_path, describe.output_path)


def test_the_layout_is_pure_deterministic_text_and_validates_its_inputs() -> None:
    forward = run_paths("C:/sup/root/")
    backward = run_paths("C:\\sup\\root")
    assert forward == backward
    assert forward.command_root == f"C:\\sup\\root\\{INV}"
    assert forward.result_path == (
        f"{forward.work_dir}\\{RESULT_MANIFEST_RELATIVE_PATH}"
    )
    assert forward.work_dir == f"C:\\sup\\root\\{INV}\\runs\\{RUN}\\work"
    assert plan_command_paths(
        "C:\\sup", command_kind=CommandKind.RUN, invocation_id=INV, run_id=RUN
    ) == plan_command_paths(
        "C:\\sup", command_kind=CommandKind.RUN, invocation_id=INV, run_id=RUN
    )
    with pytest.raises(ValidationError):
        run_paths("relative\\root")
    with pytest.raises(ValidationError):
        run_paths("C:\\sup\\..\\escape")
    with pytest.raises(ValidationError):
        plan_command_paths(
            "C:\\sup", command_kind=CommandKind.RUN, invocation_id="..", run_id=RUN
        )
    with pytest.raises(ValidationError):
        plan_command_paths(
            "C:\\sup",
            command_kind=CommandKind.RUN,
            invocation_id=INV,
            run_id="..\\..\\escape",
        )
    with pytest.raises(ValidationError):  # a VALIDATE checks the grammar too
        plan_command_paths(
            "C:\\sup",
            command_kind=CommandKind.VALIDATE,
            invocation_id=INV,
            run_id="..\\..\\escape",
        )
    with pytest.raises(TypeError, match="CommandKind"):
        plan_command_paths(
            "C:\\sup",
            command_kind="RUN",  # type: ignore[arg-type]
            invocation_id=INV,
            run_id=RUN,
        )


def test_command_paths_enforce_the_two_shapes_and_containment() -> None:
    root = f"C:\\sup\\{INV}"
    assert list(CommandPaths.model_fields) == [
        "command_root",
        "request_path",
        "output_path",
        "work_dir",
        "result_path",
    ]
    describe = CommandPaths(
        command_root=root,
        request_path=f"{root}\\request.json",
        output_path=f"{root}\\output.json",
    )
    assert describe.model_dump(mode="json") == {
        "command_root": root,
        "request_path": f"{root}\\request.json",
        "output_path": f"{root}\\output.json",
    }
    work = f"{root}\\runs\\{RUN}\\work"
    CommandPaths(
        command_root=root,
        request_path=f"{root}\\request.json",
        work_dir=work,
        result_path=f"{work}\\{RESULT_MANIFEST_RELATIVE_PATH}",
    )
    with pytest.raises(ValidationError, match="output_path"):
        CommandPaths(command_root=root, request_path=f"{root}\\request.json")
    with pytest.raises(ValidationError, match="together"):
        CommandPaths(
            command_root=root, request_path=f"{root}\\request.json", work_dir=work
        )
    with pytest.raises(ValidationError, match="output_path"):
        CommandPaths(
            command_root=root,
            request_path=f"{root}\\request.json",
            output_path=f"{root}\\output.json",
            work_dir=work,
            result_path=f"{work}\\{RESULT_MANIFEST_RELATIVE_PATH}",
        )
    with pytest.raises(ValidationError, match="lexically under"):
        CommandPaths(
            command_root=root,
            request_path="C:\\elsewhere\\request.json",
            output_path=f"{root}\\output.json",
        )
    with pytest.raises(ValidationError, match="lexically under"):
        CommandPaths(
            command_root=root,
            request_path=f"{root}\\request.json",
            output_path=root,
        )
    with pytest.raises(ValidationError, match="RESULT_MANIFEST_RELATIVE_PATH"):
        CommandPaths(
            command_root=root,
            request_path=f"{root}\\request.json",
            work_dir=work,
            result_path=f"{work}\\other.json",
        )
    with pytest.raises(ValidationError, match="extra"):
        CommandPaths.model_validate(
            {
                "command_root": root,
                "request_path": f"{root}\\request.json",
                "output_path": f"{root}\\output.json",
                "command_kind": "DESCRIBE",
            }
        )


# --------------------------------------------------------------------------
# PathPreflight and the probe (plan 7.2, reading 20)
# --------------------------------------------------------------------------


def test_path_preflight_accepts_exactly_the_two_ceiling_pairs(tmp_path: Path) -> None:
    assert list(PathPreflight.model_fields) == [
        "supervision_root",
        "long_paths_supported",
        "directory_ceiling",
        "file_ceiling",
        "probed_at_utc",
    ]
    unsupported = PathPreflight(
        supervision_root=str(tmp_path),
        long_paths_supported=False,
        directory_ceiling=DIRECTORY_CEILING_WITHOUT_LONG_PATHS,
        file_ceiling=FILE_CEILING_WITHOUT_LONG_PATHS,
        probed_at_utc=_INSTANT,
    )
    assert (unsupported.directory_ceiling, unsupported.file_ceiling) == (247, 259)
    supported = PathPreflight(
        supervision_root=str(tmp_path),
        long_paths_supported=True,
        directory_ceiling=LONG_PATH_CEILING,
        file_ceiling=LONG_PATH_CEILING,
        probed_at_utc=_INSTANT,
    )
    assert (supported.directory_ceiling, supported.file_ceiling) == (1024, 1024)
    for flag, directory, file in [
        (False, 1024, 1024),
        (True, 247, 259),
        (False, 247, 1024),
        (False, 1024, 259),
        (True, 32767, 32767),
        (False, 248, 259),
        (False, 247, 260),
    ]:
        with pytest.raises(ValidationError, match="ceiling"):
            PathPreflight(
                supervision_root=str(tmp_path),
                long_paths_supported=flag,
                directory_ceiling=directory,
                file_ceiling=file,
                probed_at_utc=_INSTANT,
            )
    with pytest.raises(ValidationError):
        PathPreflight(
            supervision_root="relative",
            long_paths_supported=False,
            directory_ceiling=247,
            file_ceiling=259,
            probed_at_utc=_INSTANT,
        )


def test_the_probe_reports_the_host_and_leaves_the_root_clean(tmp_path: Path) -> None:
    root = tmp_path / "sup"
    root.mkdir()
    preflight = ok(probe_long_path_support(str(root), now=_INSTANT))
    assert preflight.supervision_root == str(root)
    assert preflight.probed_at_utc == _INSTANT
    expected = (
        (LONG_PATH_CEILING, LONG_PATH_CEILING)
        if preflight.long_paths_supported
        else (DIRECTORY_CEILING_WITHOUT_LONG_PATHS, FILE_CEILING_WITHOUT_LONG_PATHS)
    )
    assert (preflight.directory_ceiling, preflight.file_ceiling) == expected
    assert list(root.iterdir()) == []  # the probe directory was created and removed
    # a second probe of the same root is the same answer
    assert ok(probe_long_path_support(str(root), now=_INSTANT)) == preflight


def test_the_probe_refuses_a_relative_missing_or_file_root(tmp_path: Path) -> None:
    (tmp_path / "file").write_bytes(b"")
    for root, reason in [
        ("relative\\root", "root_not_local"),
        (str(tmp_path / "absent"), "root_missing"),
        (str(tmp_path / "file"), "root_not_directory"),
    ]:
        failure = probe_long_path_support(root, now=_INSTANT)
        assert isinstance(failure, Failure), root
        assert codes_of(failure) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
        diagnostic = failure.diagnostics[0]
        assert diagnostic.details == {"reason": reason, "path_length": len(root)}
        assert diagnostic.source_component == _SUPERVISOR
        assert diagnostic.timestamp_utc == _INSTANT
        assert _missing(diagnostic.invocation_id)  # the one site with no invocation
        assert root not in diagnostic.message
        assert tmp_path.name not in diagnostic.message


def test_the_probe_refuses_a_root_that_is_itself_a_junction(tmp_path: Path) -> None:
    (tmp_path / "target").mkdir()
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        failure = probe_long_path_support(str(tmp_path / "link"), now=_INSTANT)
        assert isinstance(failure, Failure)
        assert failure.diagnostics[0].details["reason"] == "ancestor_reparse_point"
        assert list((tmp_path / "target").iterdir()) == []  # nothing probed through it
    finally:
        os.rmdir(tmp_path / "link")


# --------------------------------------------------------------------------
# preflight_command_paths (plan 7.2, 4.4)
# --------------------------------------------------------------------------


def _preflights(root: str) -> tuple[PathPreflight, PathPreflight]:
    return (
        PathPreflight(
            supervision_root=root,
            long_paths_supported=False,
            directory_ceiling=247,
            file_ceiling=259,
            probed_at_utc=_INSTANT,
        ),
        PathPreflight(
            supervision_root=root,
            long_paths_supported=True,
            directory_ceiling=1024,
            file_ceiling=1024,
            probed_at_utc=_INSTANT,
        ),
    )


def test_the_command_root_is_bounded_at_247_regardless_of_long_path_support() -> None:
    root = "C:\\" + "a" * 204  # command root = 207 + 1 + 40 = 248
    paths = run_paths(root)
    assert len(paths.command_root) == 248
    for preflight in _preflights(root):
        failure = preflight_command_paths(
            paths,
            preflight,
            now=_INSTANT,
            invocation_id=INV,
            run_id=RUN,
            experiment_id=EXP,
        )
        assert isinstance(failure, Failure)
        assert failure.diagnostics[0].details == {
            "reason": "ceiling_exceeded",
            "path_length": 248,
            "ceiling": COMMAND_ROOT_CEILING,
            "long_path_support": preflight.long_paths_supported,
        }
        assert "command root" in failure.diagnostics[0].message
        assert root not in failure.diagnostics[0].message


def test_the_work_directory_is_bounded_by_the_directory_ceiling() -> None:
    root = "C:\\" + "a" * 196  # command root 240; work dir 240 + 51 = 291
    paths = run_paths(root)
    unsupported, supported = _preflights(root)
    assert isinstance(paths.work_dir, str)
    assert len(paths.work_dir) == 291
    failure = preflight_command_paths(
        paths,
        unsupported,
        now=_INSTANT,
        invocation_id=INV,
        run_id=RUN,
        experiment_id=EXP,
    )
    assert isinstance(failure, Failure)
    assert failure.diagnostics[0].details == {
        "reason": "ceiling_exceeded",
        "path_length": 291,
        "ceiling": 247,
        "long_path_support": False,
    }
    assert "work directory" in failure.diagnostics[0].message
    assert (
        preflight_command_paths(
            paths,
            supported,
            now=_INSTANT,
            invocation_id=INV,
            run_id=RUN,
            experiment_id=EXP,
        ).outcome
        == "SUCCESS"
    )


def test_request_output_and_result_paths_are_bounded_by_the_file_ceiling() -> None:
    root = "C:\\" + "a" * 203  # command root 247 exactly; request.json = 260
    describe = plan_command_paths(
        root, command_kind=CommandKind.DESCRIBE, invocation_id=INV
    )
    unsupported, supported = _preflights(root)
    assert len(describe.command_root) == 247
    assert len(describe.request_path) == 260
    failure = preflight_command_paths(
        describe, unsupported, now=_INSTANT, invocation_id=INV
    )
    assert isinstance(failure, Failure)
    assert failure.diagnostics[0].details == {
        "reason": "ceiling_exceeded",
        "path_length": 260,
        "ceiling": 259,
        "long_path_support": False,
    }
    assert "request" in failure.diagnostics[0].message
    assert _missing(failure.diagnostics[0].run_id)  # a DESCRIBE carries no run
    assert failure.diagnostics[0].invocation_id == INV
    assert (
        preflight_command_paths(
            describe, supported, now=_INSTANT, invocation_id=INV
        ).outcome
        == "SUCCESS"
    )
    # the output and result paths are checked by the same rule
    short_root = "C:\\" + "a" * 190  # command root 234; output.json 246; request 247
    short = plan_command_paths(
        short_root, command_kind=CommandKind.DESCRIBE, invocation_id=INV
    )
    assert (
        preflight_command_paths(short, _preflights(short_root)[0], now=_INSTANT).outcome
        == "SUCCESS"
    )


def test_preflight_rejects_an_existing_reparse_component_under_the_root(
    tmp_path: Path,
) -> None:
    (tmp_path / "target").mkdir()
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / INV))
    try:
        paths = run_paths(str(tmp_path))  # the command root itself is the junction
        preflight = ok(probe_long_path_support(str(tmp_path), now=_INSTANT))
        failure = preflight_command_paths(
            paths,
            preflight,
            now=_INSTANT,
            invocation_id=INV,
            run_id=RUN,
            experiment_id=EXP,
        )
        assert isinstance(failure, Failure)
        diagnostic = failure.diagnostics[0]
        assert diagnostic.details["reason"] == "ancestor_reparse_point"
        assert diagnostic.details["path_length"] == len(paths.command_root)
        assert diagnostic.details["long_path_support"] == preflight.long_paths_supported
        correlation = (
            diagnostic.invocation_id,
            diagnostic.run_id,
            diagnostic.experiment_id,
        )
        assert correlation == (INV, RUN, EXP)
        assert diagnostic.source_component == _SUPERVISOR
        assert list((tmp_path / "target").iterdir()) == []
    finally:
        os.rmdir(tmp_path / INV)


def test_preflight_carries_no_path_text_and_requires_its_argument_types() -> None:
    root = "C:\\" + "a" * 204
    failure = preflight_command_paths(
        run_paths(root), _preflights(root)[0], now=_INSTANT
    )
    assert isinstance(failure, Failure)
    assert "aaaa" not in failure.diagnostics[0].message
    assert all(
        "aaaa" not in str(value) for value in failure.diagnostics[0].details.values()
    )
    with pytest.raises(ValueError, match="experiment"):
        preflight_command_paths(
            run_paths(root), _preflights(root)[0], now=_INSTANT, run_id=RUN
        )
    with pytest.raises(TypeError, match="CommandPaths"):
        preflight_command_paths(
            object(),  # type: ignore[arg-type]
            _preflights(root)[0],
            now=_INSTANT,
        )
    with pytest.raises(TypeError, match="PathPreflight"):
        preflight_command_paths(
            run_paths(root),
            object(),  # type: ignore[arg-type]
            now=_INSTANT,
        )


# --------------------------------------------------------------------------
# Creation, the request write and the write-boundary snapshot (plan 7.3)
# --------------------------------------------------------------------------


def test_create_command_root_is_an_exclusive_create_of_the_root_and_work_dir(
    tmp_path: Path,
) -> None:
    run = run_paths(str(tmp_path / "sup"))  # the supervision root need not exist yet
    create_command_root(run)
    assert isinstance(run.work_dir, str)
    assert Path(run.command_root).is_dir()
    assert Path(run.work_dir).is_dir()
    assert snapshot_written_paths(run.command_root) == frozenset()
    with pytest.raises(FileExistsError):
        create_command_root(run)
    describe = plan_command_paths(
        str(tmp_path / "sup"), command_kind=CommandKind.DESCRIBE, invocation_id=INV
    )
    with pytest.raises(FileExistsError):
        create_command_root(describe)  # the same invocation identity, same root
    other = plan_command_paths(
        str(tmp_path / "other"), command_kind=CommandKind.DESCRIBE, invocation_id=INV
    )
    create_command_root(other)
    assert Path(other.command_root).is_dir()
    assert list(Path(other.command_root).iterdir()) == []  # no work dir for DESCRIBE
    with pytest.raises(TypeError, match="CommandPaths"):
        create_command_root(object())  # type: ignore[arg-type]


def test_create_command_root_refuses_a_reparse_point_that_appeared_in_the_chain(
    tmp_path: Path,
) -> None:
    (tmp_path / "target").mkdir()
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        paths = run_paths(str(tmp_path / "link"))
        with pytest.raises(OSError, match="reparse point") as caught:
            create_command_root(paths)
        assert caught.value.winerror is None  # never a fabricated OS error code
        assert (tmp_path / "target" / INV).is_dir()  # created through the junction
    finally:
        os.rmdir(tmp_path / "link")


def test_write_request_file_is_an_exclusive_create_of_exact_bytes(
    tmp_path: Path,
) -> None:
    paths = plan_command_paths(
        str(tmp_path), command_kind=CommandKind.DESCRIBE, invocation_id=INV
    )
    create_command_root(paths)
    payload = b'{"schema_version":"1.0.0"}'
    write_request_file(paths.request_path, payload)
    assert Path(paths.request_path).read_bytes() == payload
    with pytest.raises(FileExistsError):
        write_request_file(paths.request_path, b"{}")
    assert Path(paths.request_path).read_bytes() == payload  # untouched
    with pytest.raises(TypeError, match="bytes"):
        write_request_file(
            str(Path(paths.command_root) / "other.json"),
            "text",  # type: ignore[arg-type]
        )
    assert not (Path(paths.command_root) / "other.json").exists()
    with pytest.raises(ValidationError):
        write_request_file("relative\\request.json", b"{}")
    assert snapshot_written_paths(paths.command_root) == frozenset({"request.json"})


def test_snapshot_records_files_and_a_junction_once_without_walking_its_target(
    tmp_path: Path,
) -> None:
    run = run_paths(str(tmp_path / "sup"))
    create_command_root(run)
    assert isinstance(run.work_dir, str)
    write_request_file(run.request_path, b"{}")
    before = snapshot_written_paths(run.command_root)
    (Path(run.work_dir) / "a.bin").write_bytes(b"a")
    (Path(run.work_dir) / "nested").mkdir()
    (Path(run.work_dir) / "nested" / "b.bin").write_bytes(b"b")
    (Path(run.command_root) / "empty").mkdir()  # a bare directory is not a write
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "secret.txt").write_bytes(b"s")
    _winapi.CreateJunction(str(target), str(Path(run.command_root) / "jx"))
    try:
        after = snapshot_written_paths(run.command_root)
    finally:
        os.rmdir(Path(run.command_root) / "jx")
    assert before == frozenset({"request.json"})
    assert after - before == frozenset(
        {
            f"runs/{RUN}/work/a.bin",
            f"runs/{RUN}/work/nested/b.bin",
            "jx",
        }
    )
    assert not any(path.endswith("secret.txt") for path in after)
    assert snapshot_written_paths(str(tmp_path / "absent")) == frozenset()


def test_snapshot_never_enters_a_root_that_became_a_reparse_point(
    tmp_path: Path,
) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "secret.txt").write_bytes(b"s")
    _winapi.CreateJunction(str(target), str(tmp_path / INV))
    try:
        assert snapshot_written_paths(str(tmp_path / INV)) == frozenset()
    finally:
        os.rmdir(tmp_path / INV)
    assert (target / "secret.txt").read_bytes() == b"s"


# --------------------------------------------------------------------------
# read_output_file (plan 7.4)
# --------------------------------------------------------------------------


def test_read_output_file_returns_exactly_the_three_member_union(
    tmp_path: Path,
) -> None:
    """The carried plan-review note: the union is ``bytes | OutputReadFailure |
    MISSING``, three members, not the former two."""
    signature = inspect.signature(read_output_file)
    assert signature.return_annotation == "bytes | OutputReadFailure | MISSING"
    assert list(signature.parameters) == ["path", "ceiling"]
    assert signature.parameters["ceiling"].kind is inspect.Parameter.KEYWORD_ONLY
    absent = read_output_file(str(tmp_path / "output.json"), ceiling=8)
    assert _missing(absent)
    (tmp_path / "output.json").write_bytes(b"{}")
    present = read_output_file(str(tmp_path / "output.json"), ceiling=8)
    assert isinstance(present, bytes)
    assert present == b"{}"
    handle = _hold_open_without_sharing(tmp_path / "output.json")
    try:
        unreadable = read_output_file(str(tmp_path / "output.json"), ceiling=8)
    finally:
        _winapi.CloseHandle(handle)
    assert isinstance(unreadable, OutputReadFailure)
    # the interpreter's ``open`` reports the CRT errno (EACCES, 13) for a sharing
    # violation, not the Win32 number 32 that ``unlink`` reports (plan 7.5); the
    # record carries the number the exception itself carried, never an invented one
    assert (unreadable.os_error_code, unreadable.error_class) == (13, "PermissionError")


def test_read_output_file_reads_zero_one_exact_and_ceiling_plus_one_bytes(
    tmp_path: Path,
) -> None:
    target = tmp_path / "output.json"
    for content, ceiling, expected in [
        (b"", 1, b""),
        (b"x", 1, b"x"),
        (b"x" * 10, 10, b"x" * 10),
        (b"x" * 11, 10, b"x" * 11),
        (b"x" * 12, 10, b"x" * 11),
        (b"x" * 200_000, 100_000, b"x" * 100_001),
    ]:
        target.write_bytes(content)
        data = read_output_file(str(target), ceiling=ceiling)
        assert isinstance(data, bytes)
        assert data == expected
    with pytest.raises(ValueError, match="ceiling"):
        read_output_file(str(target), ceiling=0)
    with pytest.raises(TypeError, match="ceiling"):
        read_output_file(str(target), ceiling=True)  # a bool is not a ceiling
    with pytest.raises(TypeError, match="ceiling"):
        read_output_file(str(target), ceiling="10")  # type: ignore[arg-type]


def test_read_output_file_refuses_a_reparse_point_and_reports_a_directory(
    tmp_path: Path,
) -> None:
    (tmp_path / "target").mkdir()
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "output.json"))
    try:
        refused = read_output_file(str(tmp_path / "output.json"), ceiling=8)
    finally:
        os.rmdir(tmp_path / "output.json")
    assert isinstance(refused, OutputReadFailure)
    assert _missing(refused.os_error_code)  # no OS call failed, so no code is invented
    assert refused.error_class == "ReparsePoint"
    (tmp_path / "dir.json").mkdir()
    directory = read_output_file(str(tmp_path / "dir.json"), ceiling=8)
    assert isinstance(directory, OutputReadFailure)
    assert isinstance(directory.os_error_code, int)
    assert directory.error_class == "PermissionError"
    assert "dir.json" not in repr(directory)
    # a parent that is a file makes the output absent, not unreadable
    (tmp_path / "file").write_bytes(b"")
    assert _missing(read_output_file(str(tmp_path / "file" / "output.json"), ceiling=8))


# --------------------------------------------------------------------------
# remove_command_root (plan 7.5)
# --------------------------------------------------------------------------


def test_remove_command_root_removes_files_before_directories_and_never_raises(
    tmp_path: Path,
) -> None:
    run = run_paths(str(tmp_path / "sup"))
    create_command_root(run)
    assert isinstance(run.work_dir, str)
    write_request_file(run.request_path, b"{}")
    (Path(run.work_dir) / "a.bin").write_bytes(b"a")
    (Path(run.work_dir) / "nested" / "deep").mkdir(parents=True)
    (Path(run.work_dir) / "nested" / "deep" / "c.bin").write_bytes(b"c")
    report = remove_command_root(run.command_root)
    assert report == CleanupReport(
        completed=(CleanupAction.COMMAND_ROOT_REMOVED,), failures=()
    )
    assert not Path(run.command_root).exists()
    assert (tmp_path / "sup").is_dir()  # the supervision root is never removed
    assert remove_command_root(run.command_root).complete  # a missing root is success


def test_remove_command_root_reports_the_sharing_violation_reason_word(
    tmp_path: Path,
) -> None:
    root = tmp_path / "inv"
    root.mkdir()
    (root / "request.json").write_bytes(b"{}")
    (root / "other.json").write_bytes(b"{}")
    with (root / "request.json").open("rb"):
        report = remove_command_root(str(root))
    assert report.completed == ()
    assert report.failures == (
        CleanupFailure(
            action=CleanupAction.COMMAND_ROOT_REMOVED, reason="sharing_violation:32"
        ),
    )
    assert "request.json" not in repr(report)
    assert root.is_dir()  # the root stays for the next pass


def test_remove_command_root_removes_a_junction_entry_without_entering_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "inv"
    root.mkdir()
    (root / "request.json").write_bytes(b"{}")
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_bytes(b"k")
    _winapi.CreateJunction(str(target), str(root / "jx"))
    report = remove_command_root(str(root))
    assert report.complete
    assert not root.exists()
    assert (target / "keep.txt").read_bytes() == b"k"  # the target was never walked


# --------------------------------------------------------------------------
# observe_executable (plan 4.1 row 1, 7.2 walk, reading 3)
# --------------------------------------------------------------------------


def test_observe_executable_reports_each_case(tmp_path: Path) -> None:
    content = b"MZ-not-really-an-executable" * 100
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(content)
    expected = sha256_bytes(content)

    verified = observe_executable(_entry(executable, expected), now=_INSTANT)
    assert isinstance(verified, ExecutableObservation)
    assert (verified.present, verified.regular_file) == (True, True)
    assert (verified.reparse_point, verified.ancestor_reparse_point) == (False, False)
    assert verified.observed_hash == expected
    assert verified.verified
    assert verified.executable_path == str(executable)
    assert verified.expected_hash == expected
    assert verified.observed_at_utc == _INSTANT

    mismatch = observe_executable(_entry(executable, "f" * 64), now=_INSTANT)
    assert mismatch.observed_hash == expected
    assert mismatch.expected_hash == "f" * 64
    assert not mismatch.verified

    absent = observe_executable(_entry(tmp_path / "absent.exe", expected), now=_INSTANT)
    assert (absent.present, absent.regular_file, absent.reparse_point) == (
        False,
        False,
        False,
    )
    assert not isinstance(absent.observed_hash, str)
    assert not absent.verified

    (tmp_path / "dir.exe").mkdir()
    directory = observe_executable(_entry(tmp_path / "dir.exe", expected), now=_INSTANT)
    assert (directory.present, directory.regular_file) == (True, False)
    assert not isinstance(directory.observed_hash, str)
    assert not directory.verified

    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "adapter.exe").write_bytes(content)
    _winapi.CreateJunction(str(tmp_path / "target"), str(tmp_path / "link"))
    try:
        through = observe_executable(
            _entry(tmp_path / "link" / "adapter.exe", expected), now=_INSTANT
        )
        assert (through.present, through.regular_file, through.reparse_point) == (
            True,
            True,
            False,
        )
        assert through.ancestor_reparse_point
        assert not isinstance(through.observed_hash, str)
        assert through.verified is False  # a matching hash is never read through it
        as_junction = observe_executable(
            _entry(tmp_path / "link", expected), now=_INSTANT
        )
        assert (as_junction.present, as_junction.reparse_point) == (True, True)
        assert as_junction.regular_file is False
        assert not as_junction.ancestor_reparse_point
        assert not isinstance(as_junction.observed_hash, str)
    finally:
        os.rmdir(tmp_path / "link")
    with pytest.raises(TypeError, match="AdapterCatalogEntry"):
        observe_executable(object(), now=_INSTANT)


def test_observe_executable_hashes_every_byte_of_a_large_file(tmp_path: Path) -> None:
    content = bytes(range(256)) * 1024  # 256 KiB, several read chunks
    executable = tmp_path / "large.exe"
    executable.write_bytes(content)
    entry = _entry(executable, sha256_bytes(content))
    assert observe_executable(entry, now=_INSTANT).verified
    executable.write_bytes(content + b"\x00")
    assert not observe_executable(entry, now=_INSTANT).verified


# --------------------------------------------------------------------------
# Purity: the reviewed import closure, no ambient path access, the exported surface
# --------------------------------------------------------------------------


def test_the_module_imports_only_its_reviewed_roots_and_reads_no_ambient_path() -> None:
    text = _module_source()
    tree = ast.parse(text)
    roots, project = _imported(tree)
    assert roots <= _PURE_ROOTS, roots - _PURE_ROOTS
    assert roots & _DENIED_ROOTS == set()
    permitted = (
        "crypto_lab.domain.",
        "crypto_lab.adapters.",
        "crypto_lab.process_supervision.",
    )
    for module in project:
        assert module.startswith(permitted), module
    assert "crypto_lab.adapters.catalog" in project
    assert "crypto_lab.adapters.limits" in project
    assert "crypto_lab.process_supervision.models" in project
    assert "crypto_lab.process_supervision.diagnostics" in project
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    ambient = {"cwd", "home", "expanduser", "resolve", "environ", "getenv"}
    assert attributes & ambient == set()
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert (identifiers | attributes) & _STAGE4_BARE_NAMES == set()
    for forbidden in (
        "datetime.now",
        "utcnow",
        "time.time",
        "random.",
        "os.environ",
        "import random",
        "uuid4(",
        "import doubles",
        "from doubles",
        "sandbox",
    ):
        assert forbidden not in text, forbidden
    assert text.startswith('"""')
    assert "from __future__ import annotations" in text


def test_the_exported_surface_is_exactly_the_plan_inventory() -> None:
    exported = list(roots_module.__all__)
    assert exported == _EXPORTED  # RUF022 order: the two records, then the functions
    for name in exported:
        assert hasattr(roots_module, name), name
    public = {
        name
        for name, value in vars(roots_module).items()
        if not name.startswith("_")
        and getattr(value, "__module__", None) == roots_module.__name__
    }
    assert public == set(_EXPORTED)
