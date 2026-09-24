"""Stage 7 Task 6: the supervisor's surface, preflight, launch edge and guard pins.

Plan 4.1, 4.3, 4.4, 6.4 rows 1-6, 7.3-7.5 and the Task 6 "plus" list: the structural
refusals that change no record, the executable observation branches, the launch
failure mapping, the envelope agreement, the write boundary, the bounded output read,
the stderr presence rule, the raw-token walk over every retained projection, the exact
public surface and protocol conformance of ``WindowsProcessSupervisor``, and the
closed-world guard expectations of plan 2.6. The ``scripted`` fixture is the loop
module's (plan 9.5), imported from the sibling test module as the safety guards do.

Test-local readings, declared rather than inferred silently:

- Carried note C (R-EXEC of the Task 6 ledger): a present regular executable whose
  bytes cannot be read is an infrastructure failure at the supervisor's boundary
  (specification 8.2, last paragraph) and is refused before the swap with
  ``CORE.INVARIANT_VIOLATION``; the ``ExecutableObservation`` record cannot represent a
  hashless regular file, so no launch-path row can carry it.
- The guard literals are read from the guard files' AST rather than imported, because
  ``tests/safety`` is not on this module's import path.
"""

from __future__ import annotations

import _winapi
import ast
import errno
import inspect
import shutil
import sys
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic.experimental.missing_sentinel import MISSING
from test_supervisor_loop import (
    CANCELLED,
    EXITED,
    FAILED_TO_START,
    PENDING,
    PROTOCOL_FAILED,
    STARTING,
    TIMED_OUT,
    TIMEOUT_SECONDS,
    _Scripted,
    codes_of,
    ok,
    primary,
    primary_code,
    run,
    scripted,
    token,
    valid_heartbeat_line,
)

from contract.harness import assert_token_absent
from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    PROTOCOL_EVENT_TOO_LARGE,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_MALFORMED_JSONL,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_UNSUPPORTED_VERSION,
)
from crypto_lab.adapters.envelopes import AdapterCommandRequestEnvelope
from crypto_lab.adapters.limits import (
    MIN_EVENT_LINE_BYTES,
    PROTOCOL_LIMITS_DEFAULT,
)
from crypto_lab.adapters.manifests import ManifestParse, ValidationResultParse
from crypto_lab.adapters.sanitization import StderrCapture
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.lifecycle import CommandKind, EngineRunState
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments.diagnostics import (
    CONCURRENCY_CONFLICT,
    IMMUTABLE_INPUT_MISMATCH,
    INVARIANT_VIOLATION,
)
from crypto_lab.process_supervision import supervisor as supervisor_module
from crypto_lab.process_supervision.diagnostics import (
    PROCESS_CLEANUP_FAILED,
    PROCESS_JOB_OBJECT_UNAVAILABLE,
    PROCESS_LAUNCH_FAILED,
    PROCESS_PATH_PREFLIGHT_REJECTED,
    PROCESS_WRITE_BOUNDARY_VIOLATION,
)
from crypto_lab.process_supervision.models import (
    DESCRIBE_STDERR_PLACEHOLDER,
    FORCED_TERMINATION_EXIT_CODE,
    CleanupAction,
    CleanupFailure,
    LaunchFailure,
    SupervisionTraceKind,
)
from crypto_lab.process_supervision.ports import ProcessSupervisor
from crypto_lab.process_supervision.roots import (
    PathPreflight,
    plan_command_paths,
    snapshot_written_paths,
)
from crypto_lab.process_supervision.supervisor import WindowsProcessSupervisor
from doubles import supervision as doubles_module
from doubles.experiments import INSTANT
from doubles.supervision import build_supervisor, supervised_catalog_entry_for

__all__ = ["scripted"]  # the re-exported fixture (F401 otherwise)

_REPOSITORY: Final = Path(__file__).resolve().parents[3]
_STAGE3_GUARD: Final = _REPOSITORY / "tests/safety/test_stage3_boundaries.py"
_PACKAGE_LAYOUT: Final = _REPOSITORY / "tests/unit/test_package_layout.py"
_TASK5_TESTS: Final = (
    _REPOSITORY / "tests/unit/experiments/test_supervision_lifecycle.py"
)
_SUPERVISOR_PATH: Final = (
    _REPOSITORY / "src/crypto_lab/process_supervision/supervisor.py"
)
#: Plan 2.6: the roots ``supervisor.py`` may import at module level (``asyncio`` is
#: function-local inside ``invoke``).
_MODULE_ROOTS: Final = frozenset(
    {
        "__future__",
        "collections",
        "contextlib",
        "dataclasses",
        "datetime",
        "enum",
        "pathlib",
        "pydantic",
        "threading",
        "typing",
        "crypto_lab",
    }
)
_DENIED_ROOTS: Final = frozenset(
    {"asyncio", "subprocess", "ctypes", "queue", "os", "sys", "time", "io", "shutil"}
)
_DENIED_PROJECT_MODULES: Final = (
    "crypto_lab.experiments",
    "crypto_lab.process_supervision.windows_api",
    "crypto_lab.process_supervision.windows_process",
    "crypto_lab.process_supervision.reconciliation",
    "crypto_lab.configuration",
    "crypto_lab.persistence",
    "crypto_lab.cli",
)
_PURITY_SUBSTRINGS: Final = (
    "time.time",
    "random.",
    "datetime.now",
    "uuid4(",
    "os.environ",
    "import random",
    "import doubles",
    "from doubles",
    "sandbox",
)
_TASK7_NAMES: Final = ("reconcile_invocations", "ReconciliationReport")


def _literal(path: Path, name: str) -> Any:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is not None and any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            return ast.literal_eval(value)
    raise AssertionError(f"{name} is not assigned a literal in {path}")


def _entries(scripted: _Scripted, kind: SupervisionTraceKind) -> list[Any]:
    return [entry for entry in scripted.observer.entries if entry.kind is kind]


def _hold_open_without_sharing(path: Path) -> int:
    """Open ``path`` with share mode 0 (the Task 3 technique)."""
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        0,
        _winapi.NULL,
        _winapi.OPEN_EXISTING,
        0,
        _winapi.NULL,
    )


# --------------------------------------------------------------------------
# Surface and protocol conformance
# --------------------------------------------------------------------------


def test_the_module_exports_exactly_the_supervisor_and_no_later_task_name() -> None:
    assert supervisor_module.__all__ == ["WindowsProcessSupervisor"]
    for name in _TASK7_NAMES:
        assert not hasattr(supervisor_module, name), name


def test_the_supervisor_satisfies_the_port_with_the_exact_invoke_signature(
    scripted: _Scripted,
) -> None:
    assert isinstance(scripted.supervisor, ProcessSupervisor)
    port = inspect.signature(ProcessSupervisor.invoke)
    implementation = inspect.signature(WindowsProcessSupervisor.invoke)
    assert [
        (parameter.name, parameter.kind, parameter.annotation)
        for parameter in implementation.parameters.values()
    ] == [
        (parameter.name, parameter.kind, parameter.annotation)
        for parameter in port.parameters.values()
    ]
    assert implementation.return_annotation == port.return_annotation
    assert inspect.iscoroutinefunction(WindowsProcessSupervisor.invoke)


def test_the_constructor_is_keyword_only_with_the_plan_defaults() -> None:
    signature = inspect.signature(WindowsProcessSupervisor.__init__)
    parameters = list(signature.parameters.values())[1:]
    assert [parameter.name for parameter in parameters] == [
        "lifecycle",
        "controller",
        "clock",
        "supervision_root",
        "supervisor_instance_id",
        "cancellation_grace_seconds",
        "describe_limits",
        "preflight",
        "observers",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in parameters
    )
    defaults = {parameter.name: parameter.default for parameter in parameters}
    assert defaults["cancellation_grace_seconds"] == 10
    assert defaults["describe_limits"] == PROTOCOL_LIMITS_DEFAULT
    assert defaults["preflight"] is MISSING
    assert defaults["observers"] == ()
    assert defaults["lifecycle"] is inspect.Parameter.empty


def test_an_over_long_supervisor_instance_id_is_refused_at_construction(
    scripted: _Scripted,
) -> None:
    # Review finding N-4: the ProcessIdentity grammar applies before any launch.
    with pytest.raises(ValueError, match="supervisor_instance_id"):
        build_supervisor(
            lifecycle=scripted.lifecycle,
            controller=scripted.controller,
            clock=scripted.clock,
            supervision_root=str(scripted.root),
            supervisor_instance_id="x" * 1025,
        )


@pytest.mark.parametrize("grace", [-1, 301])
def test_the_grace_period_is_bounded_like_the_process_configuration(
    scripted: _Scripted, grace: int
) -> None:
    with pytest.raises(ValueError, match="cancellation_grace_seconds"):
        build_supervisor(
            lifecycle=scripted.lifecycle,
            controller=scripted.controller,
            clock=scripted.clock,
            supervision_root=str(scripted.root),
            cancellation_grace_seconds=grace,
        )


def test_asyncio_is_imported_only_inside_invoke_and_the_roots_are_confined() -> None:
    source = _SUPERVISOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    module_roots: set[str] = set()
    project: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            module_roots |= {alias.name.partition(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            module_roots.add(node.module.partition(".")[0])
            project.add(node.module)
    assert module_roots <= _MODULE_ROOTS, module_roots
    assert not module_roots & _DENIED_ROOTS
    for denied in _DENIED_PROJECT_MODULES:
        assert not any(module.startswith(denied) for module in project), denied
    asyncio_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        and any(alias.name == "asyncio" for alias in node.names)
    ]
    assert len(asyncio_imports) == 1
    invoke = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "invoke"
    )
    assert asyncio_imports[0] in invoke.body
    assert source.startswith('"""')
    assert "from __future__ import annotations" in source
    for substring in _PURITY_SUBSTRINGS:
        assert substring not in source, substring


# --------------------------------------------------------------------------
# Plan 4.4: the structural preflight changes no record
# --------------------------------------------------------------------------


def _refused(scripted: _Scripted, command: AdapterCommand) -> Failure:
    result: Result[Any] = run(scripted.supervisor.invoke(command, token()))
    assert isinstance(result, Failure), result
    assert scripted.controller.launches == ()
    assert len(_entries(scripted, SupervisionTraceKind.PREFLIGHT_REFUSED)) == 1
    assert not Path(command.request_path).parent.exists()  # nothing written
    return result


def test_a_non_pending_record_is_refused_before_the_swap(scripted: _Scripted) -> None:
    scripted.start_invocation_externally()
    failure = _refused(scripted, scripted.run_command)
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    diagnostic = failure.diagnostics[0]
    assert diagnostic.details["check"] == "record_not_pending"
    assert (diagnostic.run_id, diagnostic.experiment_id) == (
        scripted.run_id,
        scripted.experiment_id,
    )  # linked_run precedes every refusal, so the ids are carried (plan 3.5)
    assert scripted.stored_invocation().state is STARTING
    assert scripted.lifecycle.calls.count("begin_start") == 0


def test_a_command_of_another_kind_or_timeout_is_refused(scripted: _Scripted) -> None:
    paths = plan_command_paths(
        str(scripted.root),
        command_kind=CommandKind.VALIDATE,
        invocation_id=scripted.invocation_id,
        run_id=scripted.run_id,
    )
    other_kind = AdapterCommand(
        command_kind=CommandKind.VALIDATE,
        catalog_entry=scripted.entry,
        invocation_id=scripted.invocation_id,
        request_path=paths.request_path,
        output_path=paths.output_path,
        timeout_seconds=TIMEOUT_SECONDS,
    )
    failure = _refused(scripted, other_kind)
    assert failure.diagnostics[0].details["check"] == "command_kind"
    scripted.reset()
    other_timeout = scripted.run_command.model_copy(update={"timeout_seconds": 5})
    failure = _refused(scripted, other_timeout)
    assert failure.diagnostics[0].details["check"] == "timeout_seconds"
    assert scripted.stored_invocation().state is PENDING


def test_another_adapter_identity_or_undecodable_launch_arguments_are_refused(
    scripted: _Scripted,
) -> None:
    other = scripted.run_command.model_copy(
        update={
            "catalog_entry": scripted.entry.model_copy(
                update={"adapter_name": "fake.warnings"}
            )
        }
    )
    failure = _refused(scripted, other)
    assert failure.diagnostics[0].details["check"] == "adapter_identity"
    scripted.reset()
    bad_arguments = scripted.run_command.model_copy(
        update={
            "catalog_entry": scripted.entry.model_copy(
                update={"runtime_metadata": {"launch_arguments": "text"}}
            )
        }
    )
    failure = _refused(scripted, bad_arguments)
    assert failure.diagnostics[0].details["check"] == "launch_arguments"


def test_a_command_whose_paths_differ_from_the_layout_is_refused(
    scripted: _Scripted, tmp_path: Path
) -> None:
    elsewhere = plan_command_paths(
        str(tmp_path / "elsewhere"),
        command_kind=CommandKind.RUN,
        invocation_id=scripted.invocation_id,
        run_id=scripted.run_id,
    )
    other = scripted.run_command.model_copy(
        update={
            "request_path": elsewhere.request_path,
            "work_dir": elsewhere.work_dir,
            "result_path": elsewhere.result_path,
        }
    )
    failure = _refused(scripted, other)
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    assert failure.diagnostics[0].details["check"] == "command_paths"


def test_a_path_over_the_ceiling_is_refused_with_the_correlated_preflight_code(
    scripted: _Scripted, tmp_path: Path
) -> None:
    # The command root stays under 247 while the RUN work directory exceeds it.
    padding = 180 - len(str(tmp_path)) - 1
    assert padding > 0, "tmp_path is unexpectedly long"
    root = tmp_path / ("a" * padding)
    root.mkdir()
    unsupported = PathPreflight(
        supervision_root=str(root),
        long_paths_supported=False,
        directory_ceiling=247,
        file_ceiling=259,
        probed_at_utc=INSTANT,
    )
    scripted.rebuild(root=root, preflight=unsupported)
    failure = _refused(scripted, scripted.run_command)
    assert codes_of(failure) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    diagnostic = failure.diagnostics[0]
    assert diagnostic.details["reason"] == "ceiling_exceeded"
    assert (diagnostic.invocation_id, diagnostic.run_id, diagnostic.experiment_id) == (
        scripted.invocation_id,
        scripted.run_id,
        scripted.experiment_id,
    )


def test_another_actor_moving_the_record_before_begin_start_returns_the_failure(
    scripted: _Scripted,
) -> None:
    scripted.lifecycle.before("begin_start", scripted.start_invocation_externally)
    result = run(scripted.supervisor.invoke(scripted.run_command, token()))
    assert isinstance(result, Failure)
    assert scripted.controller.launches == ()
    assert scripted.lifecycle.calls.count("begin_start") == 1
    assert "resolve_external_winner" not in scripted.lifecycle.calls
    stored = scripted.stored_invocation()
    assert (stored.state, stored.revision) == (STARTING, 1)  # the mover's revision


# --------------------------------------------------------------------------
# Plan 4.1 row 1 and reading 3: the executable observation
# --------------------------------------------------------------------------


def _copied_launcher(tmp_path: Path) -> Path:
    copy = tmp_path / "launcher.exe"
    shutil.copyfile(sys.executable, copy)
    return copy


@pytest.mark.parametrize("kind", [CommandKind.RUN, CommandKind.VALIDATE])
def test_an_absent_executable_fails_to_start_as_unavailable_for_linked_kinds(
    scripted: _Scripted, tmp_path: Path, kind: CommandKind
) -> None:
    copy = _copied_launcher(tmp_path)
    entry = supervised_catalog_entry_for("fake.conformant", executable=copy)
    copy.unlink()
    scripted.rebuild(entry=entry)
    command = scripted.command_of(kind)
    outcome = ok(run(scripted.supervisor.invoke(command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    assert record.process_created is False
    diagnostic = primary(record)
    assert diagnostic.error_code == ADAPTER_UNAVAILABLE
    assert diagnostic.details["reason"] == "executable_absent"
    assert (diagnostic.invocation_id, diagnostic.run_id, diagnostic.experiment_id) == (
        record.invocation_id,
        record.run_id,
        scripted.experiment_of(kind),
    )
    assert (
        scripted.stored_run(scripted.run_of(kind)).state is EngineRunState.UNAVAILABLE
    )
    assert scripted.controller.launches == ()
    assert not isinstance(outcome.command_result.stderr, StderrCapture)
    assert record.cleanup_complete
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert not outcome.executable_observation.present


def test_an_absent_executable_fails_a_describe_to_start_without_a_run(
    scripted: _Scripted, tmp_path: Path
) -> None:
    copy = _copied_launcher(tmp_path)
    entry = supervised_catalog_entry_for("fake.conformant", executable=copy)
    copy.unlink()
    scripted.rebuild(entry=entry)
    record = ok(
        run(scripted.supervisor.invoke(scripted.describe_command, token()))
    ).command_result.invocation
    assert record.state is FAILED_TO_START
    assert primary_code(record) == ADAPTER_UNAVAILABLE
    assert not isinstance(primary(record).run_id, str)


def test_a_present_executable_with_another_hash_is_an_immutable_input_mismatch(
    scripted: _Scripted,
) -> None:
    flipped = ("0" if scripted.entry.executable_hash[0] != "0" else "1") + (
        scripted.entry.executable_hash[1:]
    )
    scripted.rebuild(
        entry=scripted.entry.model_copy(update={"executable_hash": flipped})
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == IMMUTABLE_INPUT_MISMATCH
    assert diagnostic.details["reason"] == "hash_mismatch"
    assert diagnostic.details["expected_hash"] == flipped
    assert (
        diagnostic.details["observed_hash"]
        == outcome.executable_observation.observed_hash
    )
    assert scripted.stored_run().state is EngineRunState.FAILED
    assert scripted.controller.launches == ()
    assert not isinstance(outcome.command_result.stderr, StderrCapture)
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_a_directory_as_the_executable_is_a_mismatch_without_an_observed_hash(
    scripted: _Scripted, tmp_path: Path
) -> None:
    directory = tmp_path / "adapter.exe"
    directory.mkdir()
    entry = AdapterCatalogEntry(
        adapter_name=scripted.entry.adapter_name,
        adapter_version=scripted.entry.adapter_version,
        engine=scripted.entry.engine,
        executable_path=str(directory),
        executable_hash="0" * 64,
        runtime_metadata=scripted.entry.runtime_metadata,
    )
    scripted.rebuild(entry=entry)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    diagnostic = primary(record)
    assert record.state is FAILED_TO_START
    assert diagnostic.error_code == IMMUTABLE_INPUT_MISMATCH
    assert diagnostic.details["reason"] == "not_regular_file"
    assert "observed_hash" not in diagnostic.details


def test_a_regular_executable_with_unreadable_bytes_is_refused_before_the_swap(
    scripted: _Scripted, tmp_path: Path
) -> None:
    copy = _copied_launcher(tmp_path)
    scripted.rebuild(
        entry=supervised_catalog_entry_for("fake.conformant", executable=copy)
    )
    handle = _hold_open_without_sharing(copy)
    try:
        failure = _refused(scripted, scripted.run_command)
    finally:
        _winapi.CloseHandle(handle)
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    diagnostic = failure.diagnostics[0]
    assert diagnostic.details["check"] == "executable_unreadable"
    # ``open()`` reports the sharing violation as ``errno.EACCES`` (13) and sets no
    # ``winerror`` (the Task 3 finding); a raw Win32 caller would see 32.
    assert diagnostic.details["os_error_code"] in {errno.EACCES, 32}
    assert diagnostic.details["error_class"] == "PermissionError"
    assert scripted.stored_invocation().state is PENDING
    assert scripted.stored_run().state is EngineRunState.READY
    assert scripted.lifecycle.calls.count("begin_start") == 0
    assert "resolve_external_winner" not in scripted.lifecycle.calls
    # a positive control: released, the same copy is observed and verified
    scripted.reset()
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.executable_observation.verified


# --------------------------------------------------------------------------
# Plan 6.4 row 4 and 8.2: the launch failure mapping
# --------------------------------------------------------------------------


def test_a_not_found_launch_failure_is_unavailable_with_the_linked_correlation(
    scripted: _Scripted,
) -> None:
    scripted.controller.launch_failure = LaunchFailure(
        stage="popen", os_error_code=3, error_class="FileNotFoundError", not_found=True
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == ADAPTER_UNAVAILABLE
    assert diagnostic.details == {
        "reason": "create_process_not_found",
        "os_error_code": 3,
    }
    assert (diagnostic.run_id, diagnostic.experiment_id) == (
        scripted.run_id,
        scripted.experiment_id,
    )
    assert scripted.stored_run().state is EngineRunState.UNAVAILABLE
    assert isinstance(outcome.command_result.stderr, StderrCapture)  # envelope written
    assert len(_entries(scripted, SupervisionTraceKind.LAUNCH_FAILED)) == 1
    assert not Path(scripted.run_command.request_path).parent.exists()  # root removed
    assert record.cleanup_complete


def test_any_other_launch_failure_is_launch_failed_with_its_stage_and_error(
    scripted: _Scripted,
) -> None:
    scripted.controller.launch_failure = LaunchFailure(
        stage="resume", os_error_code=5, error_class="ResumeThread", not_found=False
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.validate_command, token())))
    record = outcome.command_result.invocation
    diagnostic = primary(record)
    assert record.state is FAILED_TO_START
    assert diagnostic.error_code == PROCESS_LAUNCH_FAILED
    assert diagnostic.details == {
        "stage": "resume",
        "os_error_code": 5,
        "error_class": "ResumeThread",
    }
    assert scripted.stored_run(scripted.validate_run_id).state is EngineRunState.FAILED
    assert scripted.lifecycle.calls.count("enrich") == 1
    assert scripted.controller.terminate_calls == []


# --------------------------------------------------------------------------
# Plan 4.3: envelope agreement; 7.3: the write boundary; 7.4: the output read
# --------------------------------------------------------------------------


class _DisagreeingEnvelope:
    """A lifecycle whose envelope names another invocation (a lifecycle defect)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def request_envelope(
        self, invocation_id: str
    ) -> Result[AdapterCommandRequestEnvelope]:
        result = self._inner.request_envelope(invocation_id)
        if isinstance(result, Failure):
            return result
        envelope = result.value.model_copy(
            update={"invocation_id": "inv_00000000-0000-4000-8000-000000000000"}
        )
        return Success[AdapterCommandRequestEnvelope](outcome="SUCCESS", value=envelope)


def test_an_envelope_disagreeing_with_the_record_fails_to_start_as_an_invariant(
    scripted: _Scripted,
) -> None:
    supervisor = build_supervisor(
        lifecycle=_DisagreeingEnvelope(scripted.lifecycle),
        controller=scripted.controller,
        clock=scripted.clock,
        supervision_root=str(scripted.root),
        observers=(scripted.observer,),
    )
    outcome = ok(run(supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    assert primary_code(record) == INVARIANT_VIOLATION
    assert primary(record).details["check"] == "envelope_agreement"
    assert scripted.stored_run().state is EngineRunState.FAILED
    assert scripted.controller.launches == ()
    assert not isinstance(outcome.command_result.stderr, StderrCapture)


def test_a_stray_write_outside_the_permitted_paths_is_a_boundary_violation(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    root = Path(scripted.run_command.request_path).parent
    scripted.observer.on(
        SupervisionTraceKind.LAUNCHED,
        lambda _entry: (root / "stray.txt").write_bytes(b"x"),
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert PROCESS_WRITE_BOUNDARY_VIOLATION in scripted.codes_of_ids(
        record.diagnostic_ids
    )
    violation = [
        e
        for e in outcome.trace
        if e.kind is SupervisionTraceKind.WRITE_BOUNDARY_VIOLATION
    ]
    assert len(violation) == 1
    assert violation[0].facts["stray_path_count"] == 1
    assert root.exists()  # a post-RUNNING root is never removed (reading 12)


def test_a_write_under_the_work_directory_is_permitted(scripted: _Scripted) -> None:
    scripted.exit_after = 1
    work_dir = scripted.run_command.work_dir
    assert isinstance(work_dir, str)
    scripted.observer.on(
        SupervisionTraceKind.LAUNCHED,
        lambda _entry: (Path(work_dir) / "candidate.bin").write_bytes(b"x"),
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert PROCESS_WRITE_BOUNDARY_VIOLATION not in scripted.codes_of_ids(
        record.diagnostic_ids
    )
    assert outcome.command_result.diagnostics == ()


def test_a_boundary_walk_that_fails_reports_no_violation_and_never_escapes(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review finding N-5: an `iterdir` failure is neither an exception out of
    # `invoke` nor an invented stray (the pre-launch baseline is unmeasurable too).
    scripted.exit_after = 1
    root = Path(scripted.run_command.request_path).parent
    scripted.observer.on(
        SupervisionTraceKind.LAUNCHED,
        lambda _entry: (root / "stray.txt").write_bytes(b"x"),
    )

    def failing_walk(_command_root: str) -> frozenset[str]:
        raise OSError(errno.EACCES, "scripted walk failure")

    monkeypatch.setattr(supervisor_module, "snapshot_written_paths", failing_walk)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert record.cleanup_complete
    assert PROCESS_WRITE_BOUNDARY_VIOLATION not in scripted.codes_of_ids(
        record.diagnostic_ids
    )
    assert not any(
        e.kind is SupervisionTraceKind.WRITE_BOUNDARY_VIOLATION for e in outcome.trace
    )


def test_a_failed_baseline_walk_alone_never_counts_the_request_as_a_stray(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review finding N-11: only the pre-launch baseline fails; the post-exit walk
    # succeeds and sees request.json, which is not the child's write.
    scripted.exit_after = 1
    calls: list[str] = []

    def failing_once(command_root: str) -> frozenset[str]:
        calls.append(command_root)
        if len(calls) == 1:
            raise OSError(errno.EACCES, "scripted baseline failure")
        return snapshot_written_paths(command_root)

    monkeypatch.setattr(supervisor_module, "snapshot_written_paths", failing_once)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert len(calls) == 2  # the baseline and the post-exit walk, nothing else
    assert PROCESS_WRITE_BOUNDARY_VIOLATION not in scripted.codes_of_ids(
        record.diagnostic_ids
    )
    assert not any(
        e.kind is SupervisionTraceKind.WRITE_BOUNDARY_VIOLATION for e in outcome.trace
    )


# --------------------------------------------------------------------------
# The defensive and failure branches (plan 13 coverage floor): every refusal the
# constructor, the pre-swap sequence, the root writes and the output read can take
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("describe_limits", object()),
        ("supervision_root", ""),
        ("supervisor_instance_id", ""),
        ("observers", []),
    ],
    ids=["describe_limits", "supervision_root", "supervisor_instance_id", "observers"],
)
def test_the_constructor_refuses_a_mistyped_argument(
    scripted: _Scripted, field: str, value: object
) -> None:
    arguments: dict[str, Any] = {
        "lifecycle": scripted.lifecycle,
        "controller": scripted.controller,
        "clock": scripted.clock,
        "supervision_root": str(scripted.root),
        "supervisor_instance_id": "scripted-supervisor",
    }
    arguments[field] = value
    with pytest.raises(TypeError, match=field):
        WindowsProcessSupervisor(**arguments)


def test_invoke_refuses_a_mistyped_command_or_token(scripted: _Scripted) -> None:
    bogus: Any = object()
    with pytest.raises(TypeError, match="command"):
        run(scripted.supervisor.invoke(bogus, token()))
    with pytest.raises(TypeError, match="cancellation"):
        run(scripted.supervisor.invoke(scripted.run_command, bogus))
    assert scripted.controller.launches == ()


@pytest.mark.parametrize("method", ["load", "linked_run"])
def test_a_lifecycle_failure_before_the_swap_is_returned_as_the_refusal(
    scripted: _Scripted, method: str
) -> None:
    scripted.lifecycle.fail(method, CONCURRENCY_CONFLICT)
    failure = _refused(scripted, scripted.run_command)
    assert codes_of(failure) == (CONCURRENCY_CONFLICT,)
    assert scripted.lifecycle.calls.count("begin_start") == 0


def test_unplannable_command_paths_are_refused_before_the_swap(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unplannable(*_args: object, **_kwargs: object) -> object:
        raise ValueError("scripted: the paths cannot be planned")

    monkeypatch.setattr(supervisor_module, "plan_command_paths", unplannable)
    failure = _refused(scripted, scripted.run_command)
    assert codes_of(failure) == (INVARIANT_VIOLATION,)
    assert failure.diagnostics[0].details["check"] == "command_paths"


def test_an_unreadable_executable_without_a_number_carries_its_class_only(
    scripted: _Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unreadable(*_args: object, **_kwargs: object) -> object:
        raise OSError("scripted: no error number")

    monkeypatch.setattr(supervisor_module, "observe_executable", unreadable)
    failure = _refused(scripted, scripted.run_command)
    details = failure.diagnostics[0].details
    assert details["check"] == "executable_unreadable"
    assert details["error_class"] == "OSError"
    assert "os_error_code" not in details


@pytest.mark.parametrize("site", ["executable", "ancestor"])
def test_a_reparse_point_at_or_above_the_executable_is_a_mismatch(
    scripted: _Scripted, tmp_path: Path, site: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    _winapi.CreateJunction(str(target), str(link))
    if site == "executable":
        executable = link
    else:
        (target / "adapter.exe").write_bytes(b"x")
        executable = link / "adapter.exe"
    entry = AdapterCatalogEntry(
        adapter_name=scripted.entry.adapter_name,
        adapter_version=scripted.entry.adapter_version,
        engine=scripted.entry.engine,
        executable_path=str(executable),
        executable_hash="0" * 64,
        runtime_metadata=scripted.entry.runtime_metadata,
    )
    scripted.rebuild(entry=entry)
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    diagnostic = primary(record)
    assert record.state is FAILED_TO_START
    assert diagnostic.error_code == IMMUTABLE_INPUT_MISMATCH
    expected = {"executable": "reparse_point", "ancestor": "ancestor_reparse_point"}
    assert diagnostic.details["reason"] == expected[site]
    assert "observed_hash" not in diagnostic.details


def test_a_failed_request_envelope_fails_to_start_after_the_swap(
    scripted: _Scripted,
) -> None:
    scripted.lifecycle.fail("request_envelope", INVARIANT_VIOLATION)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == INVARIANT_VIOLATION
    assert diagnostic.details == {"check": "request_envelope"}
    assert scripted.controller.launches == ()
    codes = scripted.codes_of_ids(record.diagnostic_ids)
    assert codes.count(INVARIANT_VIOLATION) == 2  # the primary and the lifecycle's
    assert scripted.stored_run().state is EngineRunState.FAILED
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_an_existing_command_root_fails_to_start_as_an_invariant_violation(
    scripted: _Scripted,
) -> None:
    Path(scripted.run_command.request_path).parent.mkdir(parents=True)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == INVARIANT_VIOLATION
    assert diagnostic.details == {"check": "command_root_exists"}
    assert scripted.controller.launches == ()
    assert scripted.stored_run().state is EngineRunState.FAILED


@pytest.mark.parametrize(
    ("function", "stage", "error", "code"),
    [
        (
            "create_command_root",
            "create_root",
            OSError(errno.EACCES, "scripted denial", None, 5),
            5,
        ),
        ("write_request_file", "write_request", OSError("scripted: bare"), None),
    ],
    ids=["create_root", "write_request"],
)
def test_a_root_or_request_write_failure_is_a_launch_failure_at_its_stage(
    scripted: _Scripted,
    monkeypatch: pytest.MonkeyPatch,
    function: str,
    stage: str,
    error: OSError,
    code: int | None,
) -> None:
    def failing(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setattr(supervisor_module, function, failing)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == PROCESS_LAUNCH_FAILED
    assert diagnostic.details["stage"] == stage
    assert diagnostic.details["error_class"] == type(error).__name__
    assert ("os_error_code" in diagnostic.details) is (code is not None)
    if code is not None:
        assert diagnostic.details["os_error_code"] == code  # winerror wins over errno
    assert scripted.controller.launches == ()
    assert scripted.stored_run().state is EngineRunState.FAILED
    assert not Path(scripted.run_command.request_path).parent.exists()


def test_a_launch_failure_without_an_error_number_carries_the_stage_and_class(
    scripted: _Scripted,
) -> None:
    scripted.controller.launch_failure = LaunchFailure(
        stage="resume", error_class="ResumeThread", not_found=False
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is FAILED_TO_START
    diagnostic = primary(record)
    assert diagnostic.error_code == PROCESS_LAUNCH_FAILED
    assert diagnostic.details == {"stage": "resume", "error_class": "ResumeThread"}
    failed = _entries(scripted, SupervisionTraceKind.LAUNCH_FAILED)
    assert failed[0].facts == {"stage": "resume", "not_found": False}


def test_a_held_job_object_without_an_error_number_names_the_fallback_only(
    scripted: _Scripted,
) -> None:
    scripted.controller.job_available = False
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    held = next(
        d
        for d in outcome.command_result.diagnostics
        if d.error_code == PROCESS_JOB_OBJECT_UNAVAILABLE
    )
    assert held.details == {"fallback": "toolhelp_descendants"}


def test_an_unreadable_output_file_marks_the_reap_and_parses_nothing(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    result_path = scripted.run_command.result_path
    assert isinstance(result_path, str)
    handles: list[int] = []

    def plant_and_hold(_entry: Any) -> None:
        Path(result_path).write_bytes(b"{}")
        handles.append(_hold_open_without_sharing(Path(result_path)))

    scripted.observer.on(SupervisionTraceKind.LAUNCHED, plant_and_hold)
    try:
        outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    finally:
        for handle in handles:
            _winapi.CloseHandle(handle)
    assert outcome.command_result.invocation.state is EXITED
    assert isinstance(outcome.output_parse, type(MISSING))
    assert isinstance(outcome.command_result.parsed_output, type(MISSING))
    reaped = [e for e in outcome.trace if e.kind is SupervisionTraceKind.EXIT_REAPED]
    assert len(reaped) == 1
    assert reaped[0].facts["output_unreadable"] is True


def test_a_validate_output_is_parsed_as_a_validation_result_for_exited(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    output_path = scripted.validate_command.output_path
    assert isinstance(output_path, str)
    scripted.observer.on(
        SupervisionTraceKind.LAUNCHED,
        lambda _entry: Path(output_path).write_bytes(b"not a validation result"),
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.validate_command, token())))
    assert outcome.command_result.invocation.state is EXITED
    parse = outcome.output_parse
    assert isinstance(parse, ValidationResultParse)
    assert isinstance(parse.failure_code, str)
    assert isinstance(outcome.command_result.parsed_output, type(MISSING))


def test_a_cleanup_failure_reason_without_a_number_carries_the_word_only(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    scripted.controller.close_failures = (
        CleanupFailure(action=CleanupAction.JOB_CLOSED, reason="close_failed"),
    )
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    assert record.cleanup_complete is False
    failed = next(
        d
        for d in outcome.command_result.diagnostics
        if d.error_code == PROCESS_CLEANUP_FAILED
    )
    assert failed.details == {
        "cleanup_action": CleanupAction.JOB_CLOSED.value,
        "error_class": "close_failed",
    }


def test_the_output_file_is_read_for_exited_only_and_at_most_ceiling_plus_one(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    result_path = scripted.run_command.result_path
    assert isinstance(result_path, str)
    oversized = b"{" + b"x" * (scripted.limits.max_manifest_bytes + 100)

    def plant(_entry: Any) -> None:
        Path(result_path).write_bytes(oversized)

    scripted.observer.on(SupervisionTraceKind.LAUNCHED, plant)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is EXITED
    parse = outcome.output_parse
    assert isinstance(parse, ManifestParse)
    assert parse.byte_length == scripted.limits.max_manifest_bytes + 1
    assert isinstance(parse.failure_code, str)
    reaped = [e for e in outcome.trace if e.kind is SupervisionTraceKind.EXIT_REAPED]
    assert len(reaped) == 1
    assert reaped[0].facts["native_exit_value"] == 0
    scripted.reset()
    scripted.advance_per_tick(0.5)
    scripted.observer.on(SupervisionTraceKind.LAUNCHED, plant)
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert outcome.command_result.invocation.state is TIMED_OUT
    assert isinstance(outcome.output_parse, type(MISSING))  # never read unless EXITED


def test_a_held_job_object_diagnostic_rides_the_terminal_transition(
    scripted: _Scripted,
) -> None:
    scripted.controller.job_available = False
    scripted.controller.job_error_code = 5
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is EXITED
    codes = scripted.codes_of_ids(record.diagnostic_ids)
    assert codes.count(PROCESS_JOB_OBJECT_UNAVAILABLE) == 1
    held = next(
        d
        for d in outcome.command_result.diagnostics
        if d.error_code == PROCESS_JOB_OBJECT_UNAVAILABLE
    )
    assert held.details == {"os_error_code": 5, "fallback": "toolhelp_descendants"}
    launched = _entries(scripted, SupervisionTraceKind.LAUNCHED)
    assert launched[0].facts["job_available"] is False


# --------------------------------------------------------------------------
# Plan 2.5 reading 5: every rejection code forces at once, without an interrupt
# --------------------------------------------------------------------------


def _too_large_line() -> bytes:
    return b"{" + b"x" * MIN_EVENT_LINE_BYTES + b"}\n"


def _artifact_escape_line(scripted: _Scripted) -> bytes:
    return scripted.heartbeat_line(
        1,
        event_type="ARTIFACT_PRODUCED",
        payload={
            "relative_path": "../escape.bin",
            "artifact_kind": "native.result",
            "media_type": "application/octet-stream",
            "declared_size_bytes": 1,
            "declared_sha256": "0" * 64,
        },
    )


REJECTIONS: Final[dict[str, Any]] = {
    PROTOCOL_STDOUT_CONTAMINATION: lambda _s: b"not json\n",
    PROTOCOL_MALFORMED_JSONL: lambda _s: b"{bad\n",
    PROTOCOL_EVENT_TOO_LARGE: lambda _s: _too_large_line(),
    PROTOCOL_UNSUPPORTED_VERSION: lambda s: s.heartbeat_line(
        1, protocol_version="9.0.0"
    ),
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION: lambda s: s.heartbeat_line(
        1, invocation_id=s.validate_invocation_id
    ),
    ARTIFACT_PATH_BOUNDARY_VIOLATION: _artifact_escape_line,
}


@pytest.mark.parametrize("code", sorted(REJECTIONS))
def test_every_rejection_code_forces_termination_without_an_interrupt(
    scripted: _Scripted, code: str
) -> None:
    scripted.stdout_chunks = [REJECTIONS[code](scripted)]
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is PROTOCOL_FAILED
    assert primary_code(record) == code
    assert scripted.controller.interrupt_calls == 0
    assert scripted.controller.terminate_calls == [FORCED_TERMINATION_EXIT_CODE]
    assert scripted.stored_run().state is EngineRunState.FAILED
    assert record.native_exit_value == FORCED_TERMINATION_EXIT_CODE


def test_a_trailing_fragment_at_end_of_stream_is_flushed_as_contamination(
    scripted: _Scripted,
) -> None:
    scripted.stdout_chunks = [b'{"a":1']
    scripted.exit_after = 1
    record = ok(
        run(scripted.supervisor.invoke(scripted.run_command, token()))
    ).command_result.invocation
    assert record.state is PROTOCOL_FAILED
    assert primary_code(record) == PROTOCOL_STDOUT_CONTAMINATION
    assert record.native_exit_value == 0  # the root's own reaped exit


# --------------------------------------------------------------------------
# Stderr presence, the describe placeholder, the raw-token walk
# --------------------------------------------------------------------------


def test_stderr_is_present_exactly_when_the_envelope_was_written(
    scripted: _Scripted,
) -> None:
    cancel = token()
    cancel.request_cancellation()
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, cancel)))
    assert outcome.command_result.invocation.state is CANCELLED
    assert not isinstance(outcome.command_result.stderr, StderrCapture)
    scripted.reset()
    scripted.stderr_chunks = [b"engine noise\n"]
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    stderr = outcome.command_result.stderr
    assert isinstance(stderr, StderrCapture)
    assert stderr.sanitized_text == "engine noise\n"
    assert not stderr.truncated


def test_the_describe_placeholder_never_appears_in_a_describe_stderr(
    scripted: _Scripted,
) -> None:
    scripted.stderr_chunks = [b"hello from describe"]
    scripted.exit_after = 1
    outcome = ok(run(scripted.supervisor.invoke(scripted.describe_command, token())))
    stderr = outcome.command_result.stderr
    assert isinstance(stderr, StderrCapture)
    assert stderr.sanitized_text == "hello from describe"
    assert DESCRIBE_STDERR_PLACEHOLDER not in str(stderr.sanitized_text)
    assert chr(0) not in str(stderr.sanitized_text)


def test_no_retained_projection_carries_the_raw_token(scripted: _Scripted) -> None:
    raw = scripted.raw_token()
    scripted.stdout_chunks = [
        valid_heartbeat_line(sequence=1),
        b"contaminated " + raw.encode("utf-8") + b"\n",
    ]
    scripted.stderr_chunks = [b"stderr carries " + raw.encode("utf-8")]
    outcome = ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    record = outcome.command_result.invocation
    assert record.state is PROTOCOL_FAILED
    needle = raw.encode("utf-8")
    for entry in outcome.trace:
        assert needle not in canonical_json_bytes(entry)
    assert needle not in canonical_json_bytes(outcome.protocol_summary)
    assert needle not in canonical_json_bytes(outcome.executable_observation)
    for diagnostic in outcome.command_result.diagnostics:
        assert needle not in canonical_json_bytes(diagnostic)
    assert needle not in canonical_json_bytes(record)
    stderr = outcome.command_result.stderr
    assert isinstance(stderr, StderrCapture)
    assert raw not in str(stderr.sanitized_text)
    for stored in scripted.store.diagnostics.live.values():
        assert needle not in canonical_json_bytes(stored)
    assert_token_absent(
        (*outcome.trace, outcome.protocol_summary, outcome.executable_observation), raw
    )
    for entry in scripted.observer.entries:  # the per-event entries too
        assert needle not in canonical_json_bytes(entry)


# --------------------------------------------------------------------------
# Plan 2.6: the guard expectations this task trips
# --------------------------------------------------------------------------


def test_the_source_allowlist_and_import_roots_name_the_supervisor_module() -> None:
    allowed = _literal(_STAGE3_GUARD, "_ALLOWED_SOURCE_FILES")
    assert "process_supervision/supervisor.py" in allowed
    assert (
        len(allowed) == 109
    )  # Stage 8 Task 4 appended the unit-of-work and repository modules
    roots = _literal(_STAGE3_GUARD, "_ALLOWED_IMPORT_ROOTS")
    assert "asyncio" in roots
    assert len(roots) == 29  # Stage 8 Task 2 added alembic
    modules = _literal(_PACKAGE_LAYOUT, "PACKAGE_MODULES")
    assert "crypto_lab.process_supervision.supervisor" in modules
    assert modules.index("crypto_lab.process_supervision.supervisor") == (
        modules.index("crypto_lab.process_supervision.windows_process") + 1
    )
    assert (
        len(modules) == 109
    )  # Stage 8 Task 4 appended the unit-of-work and repository modules


def test_the_task_five_pin_keeps_its_eleven_names_and_pins_the_nine_doubles() -> None:
    later = _literal(_TASK5_TESTS, "_LATER_TASK_NAMES")
    assert len(later) == 11  # the lifecycle-module pin is untouched
    defined = _literal(_TASK5_TESTS, "_TASK6_DOUBLES_NAMES")
    assert set(defined) == {
        "WindowsProcessSupervisor",
        "RecordingLifecycle",
        "RecordingObserver",
        "ScriptedProcess",
        "ScriptedProcessController",
        "SupervisionFixedClock",
        "RealtimeMonotonicClock",
        "build_supervisor",
        "supervised_catalog_entry_for",
    }
    assert set(later) - set(defined) == {"reconcile_invocations", "TeeController"}
    for name in defined:
        assert hasattr(doubles_module, name), name
    # Task 8 defined TeeController in the doubles (plan 9.2); reconcile_invocations
    # is the Task 7 production function and never joins the doubles.
    assert hasattr(doubles_module, "TeeController")
    assert not hasattr(doubles_module, "reconcile_invocations")


def test_the_supervision_root_is_probed_lazily_once_per_instance(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    assert not (scripted.root / ".probe").exists()  # the probe cleaned up after itself
    scripted.exit_after = 1
    second = scripted.describe_command
    outcome = ok(run(scripted.supervisor.invoke(second, token())))
    assert outcome.command_result.invocation.state is EXITED


def test_a_supervision_root_that_does_not_exist_fails_the_probe_before_any_load(
    scripted: _Scripted, tmp_path: Path
) -> None:
    supervisor = build_supervisor(
        lifecycle=scripted.lifecycle,
        controller=scripted.controller,
        clock=scripted.clock,
        supervision_root=str(tmp_path / "missing"),
    )
    result = run(supervisor.invoke(scripted.run_command, token()))
    assert codes_of(result) == (PROCESS_PATH_PREFLIGHT_REJECTED,)
    assert scripted.lifecycle.calls == []
    assert scripted.controller.launches == ()


def test_the_launch_specification_is_the_executable_prefix_and_argument_array(
    scripted: _Scripted,
) -> None:
    scripted.exit_after = 1
    ok(run(scripted.supervisor.invoke(scripted.run_command, token())))
    (specification,) = scripted.controller.launches
    command = scripted.run_command
    assert specification.invocation_id == scripted.invocation_id
    assert specification.argv[0] == scripted.entry.executable_path
    assert specification.argv[1:4] == ("-I", "-B", str(supervised_fake_path()))
    assert specification.argv[4:] == (
        "run",
        "--request",
        command.request_path,
        "--work-dir",
        command.work_dir,
        "--result",
        command.result_path,
    )
    assert specification.cwd == str(Path(command.request_path).parent)
    assert sha256_bytes(Path(specification.argv[0]).read_bytes()) == (
        scripted.entry.executable_hash
    )


def supervised_fake_path() -> Path:
    from doubles.supervision import FAKE_ADAPTER_PATH

    return FAKE_ADAPTER_PATH


def test_the_doubles_module_derives_the_merged_fake_path_without_the_harness() -> None:
    from contract.harness import FAKE_ADAPTER_PATH as harness_path

    assert supervised_fake_path() == harness_path
    doubles_source = (_REPOSITORY / "tests/doubles/supervision.py").read_text(
        encoding="utf-8"
    )
    assert "contract.harness" not in doubles_source
    assert "from contract" not in doubles_source
