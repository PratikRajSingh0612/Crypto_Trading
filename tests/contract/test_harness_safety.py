"""Stage 6 Task 8: the harness safety assertions of plan 11.3 item 5 and 14 Task 8.

The launch helper returns exactly the interpreter-prefixed argument array whose
first element is the test process's own ``sys.executable`` (never a PATH lookup,
specification 14.1), the child receives an empty environment block and no shell,
the per-scenario catalog stays inside ``MAX_CATALOG_ENTRIES`` while the distinct
scenario names exceed it, the fake adapter imports only its seven stdlib roots, no
command wrote outside its permitted paths, the scenario table is the complete and
partitioned plan inventory, and the ``PROCESS.START_TIMED_OUT`` terminal mapping is
exercised directly without a child. This module deliberately imports neither
``subprocess`` nor ``os``: it inspects the launch helper's returned arguments and
the harness source through ``ast``.

Stage 7 Task 8 adds the seam pins of plan section 9.3: the default strategy is the
stand-in (``build_harness(...).supervise is None``), the harness still holds exactly one
``Popen`` call (the seam adds a strategy object, never a second launch), ``_Supervised``
carries ``events``/``summary``/``supervision_outcome`` instead of a live ledger, and a
``CommandRun`` produced on the default path carries ``supervision_outcome is None``.
"""

from __future__ import annotations

import ast
import dataclasses
import re
import sys
from pathlib import Path

from pydantic import TypeAdapter
from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import (
    FAKE_ADAPTER_PATH,
    FAKE_ADAPTER_VERSION,
    INTERPRETER_FLAGS,
    LAUNCH_ENVIRONMENT,
    LAUNCH_SHELL,
    CommandPlan,
    CommandRun,
    OfflineCommandHarness,
    SuperviseStrategy,
    _Supervised,
    build_harness,
    catalog_entry_for,
    catalog_for,
    fake_adapter_hash,
    launch_arguments,
)
from contract.scenarios import (
    ADAPTER_SIDE_VECTORS,
    DEFAULT_TIMEOUT_SECONDS,
    PLAN_ROW_COUNT,
    SCENARIO_ENTRY_COUNT,
    SCENARIOS,
    describe_rows,
    protocol_failure_rows,
    run_rows,
    validate_rows,
)
from crypto_lab.adapters.catalog import FrozenAdapterCatalog
from crypto_lab.adapters.commands import AdapterCommand, argument_array
from crypto_lab.adapters.diagnostics import PROCESS_START_TIMED_OUT
from crypto_lab.adapters.limits import MAX_CATALOG_ENTRIES, PROTOCOL_LIMITS_DEFAULT
from crypto_lab.adapters.manifests import SanitizedAdapterResultManifest
from crypto_lab.adapters.reconciliation import SemanticReconciliation
from crypto_lab.adapters.vocabulary import ProtocolIntegrityStatus
from crypto_lab.domain.diagnostics import Diagnostic
from crypto_lab.domain.identifiers import NormalizedIdentifier
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from doubles.experiments import INSTANT, FixedClock

_C = CommandInvocationState
_R = EngineRunState
_K = CommandKind
_ALLOWED_FAKE_ROOTS = frozenset(
    {"argparse", "json", "hashlib", "sys", "os", "time", "datetime"}
)
_HARNESS_PATH = Path(__file__).resolve().parent / "harness.py"
_IDENTIFIER: TypeAdapter[str] = TypeAdapter(NormalizedIdentifier)


def _missing(value: object) -> bool:
    return value is MISSING


# --- Launch arguments and options --------------------------------------------------


def _command(root: Path, kind: CommandKind) -> AdapterCommand:
    payload: dict[str, object] = {
        "command_kind": kind,
        "catalog_entry": catalog_entry_for("fake.conformant"),
        "invocation_id": "inv_12345678-1234-4234-8234-123456789abc",
        "request_path": str(root / "request.json"),
        "timeout_seconds": 30,
    }
    if kind is _K.RUN:
        payload["work_dir"] = str(root / "runs" / "run" / "work")
        payload["result_path"] = str(root / "runs" / "run" / "work" / "manifest.json")
    else:
        payload["output_path"] = str(root / "output.json")
    return AdapterCommand.model_validate(payload)


def test_the_launch_helper_prefixes_the_own_interpreter(tmp_path: Path) -> None:
    for kind in _K:
        command = _command(tmp_path, kind)
        arguments = launch_arguments(command)
        assert arguments[0] == sys.executable
        assert arguments[1:3] == INTERPRETER_FLAGS == ("-I", "-B")
        assert arguments[3] == str(FAKE_ADAPTER_PATH)
        assert arguments[4:] == argument_array(command)
        assert Path(arguments[0]).is_absolute()
        assert Path(arguments[3]).is_absolute()


def test_the_launch_options_are_closed() -> None:
    assert LAUNCH_ENVIRONMENT == {}
    assert LAUNCH_SHELL is False
    assert FAKE_ADAPTER_PATH.is_file()
    assert FAKE_ADAPTER_PATH.name == "fake_adapter.py"
    assert FAKE_ADAPTER_PATH.parent.name == "fake_adapters"
    assert catalog_entry_for("fake.conformant").executable_hash == fake_adapter_hash()
    assert catalog_entry_for("fake.conformant").executable_path == str(
        FAKE_ADAPTER_PATH
    )


def _popen_calls(tree: ast.Module) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Popen"
    ]


def test_the_single_popen_call_passes_a_list_argv_no_shell_and_the_empty_block() -> (
    None
):
    tree = ast.parse(_HARNESS_PATH.read_text(encoding="utf-8"))
    (call,) = _popen_calls(tree)
    assert isinstance(call.func, ast.Attribute)
    assert isinstance(call.func.value, ast.Name)
    assert call.func.value.id == "subprocess"
    assert len(call.args) == 1
    assert not isinstance(call.args[0], ast.Constant)
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    assert set(keywords) == {"shell", "env", "cwd", "stdin", "stdout", "stderr"}
    shell = keywords["shell"]
    assert isinstance(shell, ast.Constant)
    assert shell.value is False
    environment = keywords["env"]
    assert isinstance(environment, ast.Name)
    assert environment.id == "LAUNCH_ENVIRONMENT"
    lines = _HARNESS_PATH.read_text(encoding="utf-8").splitlines()
    assert "# noqa: S603 - reviewed" in lines[call.lineno - 1]
    # The harness reads no environment variable to build the block.
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv"):
            raise AssertionError(f"harness reads the environment: line {node.lineno}")


# --- The fake adapter's imports ----------------------------------------------------


def _import_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            roots.add(node.module.split(".")[0])
    return roots


def test_the_fake_adapter_imports_only_its_stdlib_roots() -> None:
    tree = ast.parse(FAKE_ADAPTER_PATH.read_text(encoding="utf-8"))
    roots = _import_roots(tree)
    assert roots <= _ALLOWED_FAKE_ROOTS
    assert {"json", "hashlib", "sys"} <= roots
    assert "crypto_lab" not in roots
    assert "pydantic" not in roots
    assert "subprocess" not in roots
    source = FAKE_ADAPTER_PATH.read_text(encoding="utf-8")
    assert "print(" not in source
    assert "sys.stdout.buffer.write" in source


def test_the_fake_adapter_import_scan_detects_a_forbidden_root() -> None:
    tree = ast.parse("import json\nimport socket\nfrom crypto_lab import adapters\n")
    roots = _import_roots(tree)
    assert not roots <= _ALLOWED_FAKE_ROOTS
    assert {"socket", "crypto_lab"} <= roots


# --- The scenario inventory --------------------------------------------------------


def test_the_scenario_table_is_the_complete_plan_inventory() -> None:
    assert len(SCENARIOS) == SCENARIO_ENTRY_COUNT == 58
    assert {item.row for item in SCENARIOS} == set(range(1, PLAN_ROW_COUNT + 1))
    assert PLAN_ROW_COUNT == 52
    names = [item.name for item in SCENARIOS]
    assert len(set(names)) == len(names)
    rows = [item.row for item in SCENARIOS]
    assert rows == sorted(rows)
    assert rows.count(26) == 3
    assert rows.count(28) == 5
    for item in SCENARIOS:
        assert item.adapter_name.startswith("fake.")
        assert _IDENTIFIER.validate_python(item.adapter_name) == item.adapter_name
        assert re.fullmatch(r"row\d{2}-[a-z0-9-]+-(describe|validate|run)", item.name)
        assert item.name.endswith(item.command.value.lower())
        if item.command is _K.DESCRIBE:
            assert item.run_state is None
        else:
            assert item.run_state is not None
        if item.core_won:
            assert item.verdict is None
            assert item.native_exit is None
        else:
            assert item.verdict is not None
            assert item.native_exit is not None
        assert item.sanitized_manifest is (item.semantic_status is not None)


def test_the_four_selectors_partition_the_table() -> None:
    selections = (describe_rows(), validate_rows(), run_rows(), protocol_failure_rows())
    combined = [item for selection in selections for item in selection]
    assert sorted(combined, key=lambda item: item.name) == sorted(
        SCENARIOS, key=lambda item: item.name
    )
    assert len(combined) == len(SCENARIOS)
    assert all(item.command is _K.DESCRIBE for item in describe_rows())
    assert all(item.command is _K.VALIDATE for item in validate_rows())
    assert all(item.command is _K.RUN and not item.core_won for item in run_rows())
    assert all(
        item.command is _K.RUN and item.core_won for item in protocol_failure_rows()
    )
    assert len(describe_rows()) == 5
    assert len(validate_rows()) == 8
    assert len(run_rows()) == 28
    assert len(protocol_failure_rows()) == 17
    assert len(ADAPTER_SIDE_VECTORS) == 5


def test_every_scenario_catalog_is_one_entry_and_the_names_exceed_the_bound() -> None:
    clock = FixedClock(INSTANT)
    names = {item.adapter_name for item in SCENARIOS}
    assert len(names) > MAX_CATALOG_ENTRIES
    assert MAX_CATALOG_ENTRIES == 32
    for name in sorted(names):
        catalog = catalog_for(name, clock)
        assert isinstance(catalog, FrozenAdapterCatalog)
        assert len(catalog.list_registered()) == 1 <= MAX_CATALOG_ENTRIES
        entry = catalog.list_registered()[0]
        assert (entry.adapter_name, entry.adapter_version) == (
            name,
            FAKE_ADAPTER_VERSION,
        )
        assert entry.executable_hash == fake_adapter_hash()
        assert entry.runtime_metadata == {}


# --- Write boundaries --------------------------------------------------------------


def test_describe_validate_and_run_write_only_their_permitted_paths(
    tmp_path: Path,
) -> None:
    harness = build_harness(
        tmp_path, "fake.conformant", limits=PROTOCOL_LIMITS_DEFAULT, seed="task8-safety"
    )
    described = harness.describe(
        "fake.conformant", FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    assert described.written_paths == frozenset({"output.json"})
    assert described.work_dir == described.command_root
    experiment = harness.new_experiment("fake.conformant")
    _experiment, run = harness.new_attempt(experiment)
    run = harness.validating(run)
    validated = harness.validate(run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS)
    assert validated.written_paths == frozenset({"output.json"})
    assert validated.outcome is not None
    executed = harness.run(
        validated.outcome.run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    prefix = f"runs/{run.run_id}/work/"
    assert executed.written_paths
    assert all(path.startswith(prefix) for path in executed.written_paths)
    assert executed.work_dir == executed.command_root / "runs" / run.run_id / "work"
    # The command roots are distinct per invocation and all under the harness root.
    roots = {described.command_root, validated.command_root, executed.command_root}
    assert len(roots) == 3
    assert all(root.parent == tmp_path for root in roots)
    assert all(
        root.name == invocation.invocation_id
        for root, invocation in zip(
            (described.command_root, validated.command_root, executed.command_root),
            (
                described.command_result.invocation,
                validated.command_result.invocation,
                executed.command_result.invocation,
            ),
            strict=True,
        )
    )
    for result in (described, validated, executed):
        assert result.command_result.protocol_integrity is (
            ProtocolIntegrityStatus.INTACT
        )
        assert result.command_result.invocation.state is _C.EXITED


# --- The PROCESS.START_TIMED_OUT direct case -----------------------------------------


def test_a_start_deadline_terminalizes_the_starting_pair_without_a_child(
    tmp_path: Path,
) -> None:
    harness = build_harness(
        tmp_path, "fake.conformant", limits=PROTOCOL_LIMITS_DEFAULT, seed="task8-start"
    )
    experiment = harness.new_experiment("fake.conformant")
    _experiment, run = harness.new_attempt(experiment)
    run = harness.ready(run)
    pair = harness.launch_pair(run, timeout_seconds=DEFAULT_TIMEOUT_SECONDS)
    assert (pair.invocation.state, pair.run.state) == (_C.STARTING, _R.STARTING)
    terminal = harness.terminalize_timed_out(
        pair.invocation, pair.run, code=PROCESS_START_TIMED_OUT
    )
    assert (terminal.invocation.state, terminal.run.state) == (
        _C.TIMED_OUT,
        _R.TIMED_OUT,
    )
    assert terminal.invocation.process_created is False
    assert _missing(terminal.invocation.native_exit_value)
    assert harness.primary_code_of(terminal.invocation) == PROCESS_START_TIMED_OUT
    assert (
        terminal.run.primary_terminal_diagnostic_id
        == terminal.invocation.primary_diagnostic_id
    )
    assert harness.stored_run(run.run_id) == terminal.run
    assert (
        harness.stored_invocation(pair.invocation.invocation_id) == terminal.invocation
    )


def _content(result: CommandRun) -> tuple[object, ...]:
    """A reconciliation's order-independent content: verdict, code, status and the
    declared candidates; drawn identities are excluded by construction."""
    reconciliation = result.reconciliation
    assert isinstance(reconciliation, SemanticReconciliation)
    manifest = reconciliation.sanitized_manifest
    declarations: tuple[tuple[str, str, int, str], ...] = ()
    if isinstance(manifest, SanitizedAdapterResultManifest):
        declarations = tuple(
            (
                item.artifact_kind,
                item.media_type,
                item.declared_size_bytes,
                item.declared_sha256,
            )
            for item in manifest.candidate_declarations
        )
    primary = reconciliation.primary_diagnostic
    code = primary.error_code if isinstance(primary, Diagnostic) else None
    return (reconciliation.verdict, code, reconciliation.semantic_status, declarations)


def test_scenarios_reach_the_same_content_in_either_order(tmp_path: Path) -> None:
    """Prompt section 22: two harnesses over the same seed drive a describe and a
    run in opposite orders; every authoritative verdict and content is identical
    and each store holds only its own records, so no vector leaks into the next."""
    forward = build_harness(
        tmp_path / "forward",
        "fake.conformant",
        limits=PROTOCOL_LIMITS_DEFAULT,
        seed="task8-order",
    )
    described_first = forward.describe(
        "fake.conformant", FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    run_second = forward.drive(
        "fake.conformant", _K.RUN, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    reverse = build_harness(
        tmp_path / "reverse",
        "fake.conformant",
        limits=PROTOCOL_LIMITS_DEFAULT,
        seed="task8-order",
    )
    run_first = reverse.drive(
        "fake.conformant", _K.RUN, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    described_second = reverse.describe(
        "fake.conformant", FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    assert described_first.reconciliation == described_second.reconciliation
    assert _content(run_second) == _content(run_first)
    # Identities are drawn per kind, so the run id (the first `run` draw) agrees while
    # the invocation ids (the first and second `invocation` draws) swap between orders.
    assert run_second.written_paths == run_first.written_paths
    assert (
        run_second.command_result.invocation.invocation_id
        != run_first.command_result.invocation.invocation_id
    )
    assert (
        described_first.command_result.invocation.invocation_id
        == run_first.command_result.invocation.invocation_id
    )
    for harness in (forward, reverse):
        assert len(harness.store.committed_experiments()) == 1
        assert len(harness.store.committed_engine_runs()) == 1
        assert len(harness.store.committed_command_invocations()) == 2
    assert forward.store is not reverse.store
    assert forward.store.committed_run_events() != reverse.store.committed_run_events()
    assert [event.event_type for event in forward.store.committed_run_events()] == [
        event.event_type for event in reverse.store.committed_run_events()
    ]


def test_the_harness_is_a_named_stand_in_and_not_a_supervisor() -> None:
    source = _HARNESS_PATH.read_text(encoding="utf-8")
    assert "stand-in" in source
    tree = ast.parse(source)
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    assert "ProcessSupervisor" not in names
    assert "RunManifest" not in names
    assert "ArtifactRef" not in names
    assert isinstance(OfflineCommandHarness, type)


# --- The Stage 7 seam (plan 9.3; Stage 7 Task 8) --------------------------------------


def test_the_default_strategy_is_the_stand_in_and_the_harness_keeps_one_popen(
    tmp_path: Path,
) -> None:
    harness = build_harness(
        tmp_path, "fake.conformant", limits=PROTOCOL_LIMITS_DEFAULT, seed="seam"
    )
    assert harness.supervise is None
    assert type(harness.clock) is FixedClock
    assert harness.clock.now_utc() == INSTANT
    (call,) = _popen_calls(ast.parse(_HARNESS_PATH.read_text(encoding="utf-8")))
    assert isinstance(call.func, ast.Attribute)
    assert isinstance(call.func.value, ast.Name)
    assert call.func.value.id == "subprocess"
    # The seam never imports the Stage 7 doubles: no cycle with tests/doubles.
    source = _HARNESS_PATH.read_text(encoding="utf-8")
    assert "doubles.supervision" not in source


def test_the_supervised_record_is_relaxed_for_the_seam() -> None:
    fields = {field.name for field in dataclasses.fields(_Supervised)}
    assert {"events", "summary", "supervision_outcome"} <= fields
    assert "ledger" not in fields
    # The fourth relaxation (Task 8 reading R13): a terminal decided before any launch
    # has no stderr capture, so the field admits None; the default path always fills it.
    (stderr_field,) = (
        field for field in dataclasses.fields(_Supervised) if field.name == "stderr"
    )
    assert stderr_field.type == "StderrCapture | None"
    assert "supervision_outcome" in {
        field.name for field in dataclasses.fields(CommandRun)
    }
    plan_fields = [field.name for field in dataclasses.fields(CommandPlan)]
    assert plan_fields == [
        "invocation",
        "run",
        "material",
        "cancel_after_first_heartbeat",
        "stale_output_bytes",
    ]
    assert CommandPlan.__dataclass_params__.frozen  # type: ignore[attr-defined]
    members = {name for name in dir(SuperviseStrategy) if not name.startswith("_")}
    assert members == {"clock", "supervise"}
    assert getattr(SuperviseStrategy, "_is_protocol", False) is True


def test_the_default_strategy_yields_no_supervision_outcome(tmp_path: Path) -> None:
    harness = build_harness(
        tmp_path, "fake.conformant", limits=PROTOCOL_LIMITS_DEFAULT, seed="seam-none"
    )
    described = harness.describe(
        "fake.conformant", FAKE_ADAPTER_VERSION, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    assert described.supervision_outcome is None
    assert described.command_result.invocation.state is _C.EXITED
    experiment = harness.new_experiment("fake.conformant")
    _experiment, run = harness.new_attempt(experiment)
    validated = harness.validate(
        harness.validating(run), timeout_seconds=DEFAULT_TIMEOUT_SECONDS
    )
    assert validated.supervision_outcome is None
    assert validated.protocol_summary is not None
    assert validated.protocol_summary.accepted_count == 2
