"""Stage 7 Task 2: the trust-class-P/K supervision records (plan sections 3.3, 4.2,
6.1, 7.4 and 8.1).

Every record is a strict frozen ``CanonicalModel`` that rejects unknown fields,
unpublished, with no ``$id`` and no envelope version; absence is ``MISSING``, never
``None``; no field is annotated ``AttemptToken``, holds bytes or a float, and no
record holds an adapter byte. The cases below pin the exported inventory and field
order, every co-occurrence rule row by row, the plan 6.1 constants, the creation
identity grammar, the fixed launch-argument reader, the retained-trace rules that
keep a ``SupervisionOutcome`` bounded and canonicalisable, and the ``OutputReadFailure``
record of plan 7.4 that the Task 3 output read returns.
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, fields, is_dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from contract.harness import catalog_entry_for
from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import CommandResult
from crypto_lab.adapters.diagnostics import (
    ARTIFACT_RESULT_MANIFEST_INVALID,
    PROTOCOL_DESCRIBE_OUTPUT_INVALID,
    PROTOCOL_STDOUT_CONTAMINATION,
    PROTOCOL_VALIDATION_RESULT_INVALID,
    stage6_diagnostic,
)
from crypto_lab.adapters.events import EventRejected, ProtocolEventSummary
from crypto_lab.adapters.limits import (
    MAX_DESCRIPTOR_OUTPUT_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
)
from crypto_lab.adapters.manifests import (
    AdapterValidationResult,
    ManifestParse,
    ValidationResultParse,
    parse_validation_result,
)
from crypto_lab.adapters.negotiation import (
    BootstrapDescriptorEnvelope,
    DescriptorParse,
    parse_bootstrap_descriptor,
)
from crypto_lab.adapters.sanitization import ContaminationSample
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    ProtocolIntegrityStatus,
)
from crypto_lab.domain.base import SCHEMA_VERSION, CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import MAX_PID
from crypto_lab.domain.descriptors import (
    MAX_EXECUTABLE_PATH_CHARACTERS,
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)
from crypto_lab.domain.hashing import attempt_token_hash, request_id_for, sha256_bytes
from crypto_lab.domain.lifecycle import (
    RECOGNIZED_NATIVE_EXIT_VALUES,
    CommandInvocationState,
    CommandKind,
    EngineRunState,
    ExperimentState,
)
from crypto_lab.domain.time import format_utc
from crypto_lab.process_supervision import models as models_module
from crypto_lab.process_supervision.models import (
    COMMAND_ROOT_CEILING,
    CREATE_SUSPENDED,
    CTRL_BREAK_EVENT,
    DESCRIBE_STDERR_PLACEHOLDER,
    DIRECTORY_CEILING_WITHOUT_LONG_PATHS,
    FILE_CEILING_WITHOUT_LONG_PATHS,
    FORCED_TERMINATION_EXIT_CODE,
    LAUNCH_ARGUMENTS_KEY,
    LONG_PATH_CEILING,
    MAX_LAUNCH_ARGUMENTS,
    PIPE_HOLDER_GRACE_SECONDS,
    POST_TERMINATION_WAIT_SECONDS,
    QUEUE_CAPACITY_CHUNKS,
    READ_CHUNK_BYTES,
    READER_JOIN_SECONDS,
    TICK_SECONDS,
    CleanupAction,
    CleanupFailure,
    CleanupReport,
    CreationIdentity,
    DescendantIdentity,
    ExecutableObservation,
    InterruptOutcome,
    InvocationReconciliation,
    LaunchFailure,
    LaunchSpecification,
    OutputReadFailure,
    ProcessInspection,
    ProcessPresence,
    ReconciliationAction,
    ReconciliationReport,
    RunReconciliationFacts,
    SupervisionOutcome,
    SupervisionTraceEntry,
    SupervisionTraceKind,
    TerminationReport,
    catalog_launch_arguments,
    parse_creation_identity,
    render_creation_identity,
)
from doubles.experiments import (
    ATTEMPT_TOKEN,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    RUN_ID,
    sample_invocation,
    sample_process_identity,
)

_C = CommandInvocationState
_K = CommandKind
EXP: Final = EXPERIMENT_ID
RUN: Final = RUN_ID
INV: Final = INVOCATION_ID
SC: Final = "process_supervision.supervisor"
_INSTANT: Final = INSTANT
_HASH: Final = "a" * 64
_OTHER_HASH: Final = "b" * 64
_EXECUTABLE: Final = r"C:\adapters\alpha\adapter.exe"
_ROOT: Final = r"C:\supervision\inv"
_OTHER_INV: Final = f"inv_2{INV[5:]}"
_RECORDS: tuple[type[CanonicalModel], ...] = (
    ExecutableObservation,
    LaunchSpecification,
    ProcessInspection,
    LaunchFailure,
    OutputReadFailure,
    CleanupFailure,
    CleanupReport,
    DescendantIdentity,
    TerminationReport,
    SupervisionTraceEntry,
    SupervisionOutcome,
    RunReconciliationFacts,
    InvocationReconciliation,
    ReconciliationReport,
)
_FIELD_ORDER: dict[type[CanonicalModel], list[str]] = {
    ExecutableObservation: [
        "executable_path",
        "expected_hash",
        "present",
        "regular_file",
        "reparse_point",
        "ancestor_reparse_point",
        "observed_hash",
        "observed_at_utc",
    ],
    LaunchSpecification: ["invocation_id", "argv", "cwd"],
    ProcessInspection: [
        "identity",
        "presence",
        "observed_creation_identity",
        "observed_image_path",
    ],
    LaunchFailure: ["stage", "os_error_code", "error_class", "not_found"],
    OutputReadFailure: ["os_error_code", "error_class"],
    CleanupFailure: ["action", "reason"],
    CleanupReport: ["completed", "failures"],
    DescendantIdentity: ["pid", "creation_identity", "image_path"],
    TerminationReport: [
        "forced",
        "exit_code_used",
        "job_terminated",
        "descendants",
        "failures",
    ],
    SupervisionTraceEntry: [
        "kind",
        "invocation_id",
        "sequence",
        "at_utc",
        "monotonic_100ns",
        "facts",
        "rejection",
    ],
    SupervisionOutcome: [
        "command_result",
        "output_parse",
        "protocol_summary",
        "stdout_byte_count",
        "replay_count",
        "executable_observation",
        "trace",
    ],
    RunReconciliationFacts: [
        "run_id",
        "experiment_id",
        "run_state",
        "run_revision",
        "attempt_token_hash",
        "request_hash",
        "experiment_state",
    ],
    InvocationReconciliation: [
        "invocation_id",
        "command_kind",
        "state_before",
        "action",
        "record_after",
        "presence",
        "manifest_present",
        "diagnostics",
    ],
    ReconciliationReport: ["supervisor_instance_id", "started_at_utc", "entries"],
}
_TRACE_KINDS = [
    "PREFLIGHT_ACCEPTED",
    "PREFLIGHT_REFUSED",
    "EXECUTABLE_OBSERVED",
    "STARTING_COMMITTED",
    "REQUEST_WRITTEN",
    "LAUNCHED",
    "LAUNCH_FAILED",
    "PRE_HANDOFF_DEADLINE",
    "PRE_HANDOFF_CANCELLATION",
    "RUNNING_COMMITTED",
    "EVENT_ACCEPTED",
    "EVENT_REPLAYED",
    "EVENT_REJECTED",
    "STDOUT_BYTES_COUNTED",
    "HEARTBEAT_MISSED",
    "CANCELLATION_OBSERVED",
    "INTERRUPT_SENT",
    "INTERRUPT_UNAVAILABLE",
    "FORCED_TERMINATION",
    "EXIT_REAPED",
    "TERMINAL_DECIDED",
    "TERMINAL_COMMITTED",
    "EXTERNAL_TERMINAL_WINNER",
    "ENRICHMENT_COMMITTED",
    "CLEANUP_ACTION",
    "CLEANUP_FAILED",
    "WRITE_BOUNDARY_VIOLATION",
    "RECONCILIATION_DECISION",
]
_RECONCILIATION_ACTIONS = [
    "LEFT_PENDING",
    "TERMINALIZED_FAILED_TO_START",
    "TERMINALIZED_TIMED_OUT",
    "TERMINALIZED_CANCELLED",
    "TERMINALIZED_PROTOCOL_FAILED",
    "LEFT_RUNNING_AWAITING_DEADLINE",
    "CLEANUP_COMPLETED",
    "CLEANUP_FAILED",
    "CLEANUP_STILL_FAILING",
    "INVARIANT_REPORTED",
    "SKIPPED_EXTERNAL_WINNER",
]
_CLEANUP_ACTIONS = [
    "TREE_VERIFIED_DEAD",
    "JOB_CLOSED",
    "PROCESS_HANDLE_CLOSED",
    "STDOUT_READER_STOPPED",
    "STDERR_READER_STOPPED",
    "PIPES_CLOSED",
    "COMMAND_ROOT_REMOVED",
]
_CONSTANTS: dict[str, object] = {
    "TICK_SECONDS": 0.02,
    "READ_CHUNK_BYTES": 65_536,
    "QUEUE_CAPACITY_CHUNKS": 64,
    "POST_TERMINATION_WAIT_SECONDS": 5.0,
    "READER_JOIN_SECONDS": 5.0,
    "PIPE_HOLDER_GRACE_SECONDS": 1.0,
    "FORCED_TERMINATION_EXIT_CODE": 1067,
    "CTRL_BREAK_EVENT": 1,
    "CREATE_SUSPENDED": 0x00000004,
    "LAUNCH_ARGUMENTS_KEY": "launch_arguments",
    "MAX_LAUNCH_ARGUMENTS": 16,
    "COMMAND_ROOT_CEILING": 247,
    "DIRECTORY_CEILING_WITHOUT_LONG_PATHS": 247,
    "FILE_CEILING_WITHOUT_LONG_PATHS": 259,
    "LONG_PATH_CEILING": 1024,
}
#: The plan 2.6 import closure of ``models.py``.
_PURE_ROOTS = frozenset(
    {"__future__", "re", "dataclasses", "enum", "typing", "pydantic", "crypto_lab"}
)
_STAGE4_BARE_NAMES = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader"}
)


def _missing(value: object) -> bool:
    return value is MISSING


# --- Test helpers (plan Task 2 "Test helpers", one clause each) ------------------


def entry_with(metadata: dict[str, object]) -> AdapterCatalogEntry:
    """An ``AdapterCatalogEntry`` cloned from ``catalog_entry_for("fake.conformant")``
    with ``runtime_metadata=metadata``."""
    payload = catalog_entry_for("fake.conformant").model_dump(mode="python")
    payload["runtime_metadata"] = metadata
    return AdapterCatalogEntry.model_validate(payload)


def exited_run_result(**overrides: object) -> CommandResult:
    """A ``CommandResult`` over ``sample_invocation(state=EXITED, kind=RUN)``."""
    payload: dict[str, object] = {
        "invocation": sample_invocation(_C.EXITED, kind=_K.RUN),
        "protocol_integrity": ProtocolIntegrityStatus.INTACT,
        "accepted_events": (),
        "diagnostics": (),
        "cancelled": False,
        "timed_out": False,
    }
    payload.update(overrides)
    return CommandResult.model_validate(payload)


def result_for(
    state: CommandInvocationState, kind: CommandKind, **overrides: object
) -> CommandResult:
    integrity = (
        ProtocolIntegrityStatus.VIOLATED
        if state is _C.PROTOCOL_FAILED
        else ProtocolIntegrityStatus.INTACT
    )
    return exited_run_result(
        invocation=sample_invocation(state, kind=kind),
        protocol_integrity=integrity,
        cancelled=state is _C.CANCELLED,
        timed_out=state is _C.TIMED_OUT,
        **overrides,
    )


def _descriptor() -> AdapterDescriptor:
    return AdapterDescriptor.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "adapter_name": "fake.conformant",
            "adapter_version": "1.0.0",
            "engine": EngineDescriptor.model_validate(
                {
                    "schema_version": SCHEMA_VERSION,
                    "engine_name": "fake.engine",
                    "engine_version": "1.0.0",
                    "engine_family": "fake.family",
                    "planned_role": "Offline fake adapter.",
                    "known_limitations": (),
                }
            ),
            "supported_protocol_versions": ("1.0.0",),
            "supported_schema_versions": tuple(
                SupportedSchemaVersion(schema_name=name, schema_version=SCHEMA_VERSION)
                for name in NEGOTIABLE_SCHEMA_NAMES
            ),
            "capability_vocabulary_version": "capabilities/v1",
            "native_capabilities": ("data.ohlcv", "market.spot"),
            "approximated_capabilities": (),
            "unsupported_capabilities": (),
            "supported_operating_systems": (OperatingSystem.WINDOWS,),
            "runtime_requirements": ("CPython 3.12",),
            "network_required": False,
            "credentials_required": False,
            "known_modeling_limitations": (),
            "executable_hash": _HASH,
        }
    )


def descriptor_parse() -> DescriptorParse:
    """A ``DescriptorParse`` from ``parse_bootstrap_descriptor`` over a valid
    bootstrap document."""
    descriptor = _descriptor()
    envelope = BootstrapDescriptorEnvelope.model_validate(
        {
            "bootstrap_schema_version": SCHEMA_VERSION,
            "adapter_name": descriptor.adapter_name,
            "adapter_version": descriptor.adapter_version,
            "engine_name": descriptor.engine.engine_name,
            "engine_version": descriptor.engine.engine_version,
            "executable_hash": descriptor.executable_hash,
            "supported_protocol_versions": descriptor.supported_protocol_versions,
            "supported_schema_versions": descriptor.supported_schema_versions,
            "capability_vocabulary_versions": (
                descriptor.capability_vocabulary_version,
            ),
            "descriptor_payload_hash": sha256_bytes(canonical_json_bytes(descriptor)),
            "descriptor": descriptor,
        }
    )
    return parse_bootstrap_descriptor(
        canonical_json_bytes(envelope), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES
    )


def failed_descriptor_parse() -> DescriptorParse:
    return DescriptorParse(
        byte_length=2, source_hash=_HASH, failure_code=PROTOCOL_DESCRIBE_OUTPUT_INVALID
    )


def failed_validation_parse() -> ValidationResultParse:
    return ValidationResultParse(
        byte_length=2,
        source_hash=_HASH,
        failure_code=PROTOCOL_VALIDATION_RESULT_INVALID,
        redactions=0,
    )


def failed_manifest_parse() -> ManifestParse:
    return ManifestParse(
        byte_length=2,
        source_hash=_HASH,
        failure_code=ARTIFACT_RESULT_MANIFEST_INVALID,
        redactions=0,
    )


def validation_parse() -> ValidationResultParse:
    """A ``ValidationResultParse`` holding its strict result, through the merged
    parser over a conformant token-free ``VALID`` document."""
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "protocol_version": "1.0.0",
        "request_id": request_id_for(RUN),
        "invocation_id": INV,
        "run_id": RUN,
        "attempt_token_hash": attempt_token_hash(ATTEMPT_TOKEN),
        "outcome": "VALID",
        "diagnostics": [],
        "validated_at_utc": format_utc(_INSTANT),
    }
    document["result_hash"] = sha256_bytes(canonical_json_bytes(document))
    return parse_validation_result(
        canonical_json_bytes(document),
        max_bytes=MAX_VALIDATION_RESULT_BYTES,
        token=ATTEMPT_TOKEN,
    )


def observation(**overrides: object) -> ExecutableObservation:
    payload: dict[str, object] = {
        "executable_path": _EXECUTABLE,
        "expected_hash": _HASH,
        "present": True,
        "regular_file": True,
        "reparse_point": False,
        "ancestor_reparse_point": False,
        "observed_hash": _HASH,
        "observed_at_utc": _INSTANT,
    }
    payload.update(overrides)
    return ExecutableObservation.model_validate(payload)


def empty_summary(**overrides: object) -> ProtocolEventSummary:
    payload: dict[str, object] = {
        "accepted_count": 0,
        "last_sequence": 0,
        "artifact_declarations": (),
        "warnings": (),
        "adapter_diagnostics": (),
        "redactions": 0,
    }
    payload.update(overrides)
    return ProtocolEventSummary.model_validate(payload)


def outcome_with(**overrides: object) -> SupervisionOutcome:
    """A valid ``SupervisionOutcome`` over an ``EXITED`` RUN record with every
    required field, the given fields replaced."""
    payload: dict[str, object] = {
        "command_result": exited_run_result(),
        "protocol_summary": empty_summary(),
        "stdout_byte_count": 0,
        "replay_count": 0,
        "executable_observation": observation(),
        "trace": (),
    }
    payload.update(overrides)
    return SupervisionOutcome.model_validate(payload)


def trace_entry_with(**overrides: object) -> SupervisionTraceEntry:
    """Likewise for ``SupervisionTraceEntry``."""
    payload: dict[str, object] = {
        "kind": SupervisionTraceKind.LAUNCHED,
        "invocation_id": INV,
        "sequence": 1,
        "at_utc": _INSTANT,
        "monotonic_100ns": 0,
        "facts": {},
    }
    payload.update(overrides)
    return SupervisionTraceEntry.model_validate(payload)


def rejection() -> EventRejected:
    return EventRejected(
        outcome="REJECTED",
        diagnostic=stage6_diagnostic(
            PROTOCOL_STDOUT_CONTAMINATION,
            "contaminated",
            source_component="adapters.events",
            timestamp_utc=_INSTANT,
            invocation_id=INV,
        ),
        sample=ContaminationSample(byte_length=3, source_hash=_HASH),
    )


def cleanup_failure(action: CleanupAction = CleanupAction.JOB_CLOSED) -> CleanupFailure:
    return CleanupFailure(action=action, reason="sharing_violation:32")


def facts(**overrides: object) -> RunReconciliationFacts:
    payload: dict[str, object] = {
        "run_id": RUN,
        "experiment_id": EXP,
        "run_state": EngineRunState.RUNNING,
        "run_revision": 3,
        "attempt_token_hash": _HASH,
        "request_hash": _OTHER_HASH,
        "experiment_state": ExperimentState.RUNNING,
    }
    payload.update(overrides)
    return RunReconciliationFacts.model_validate(payload)


def reconciliation(**overrides: object) -> InvocationReconciliation:
    payload: dict[str, object] = {
        "invocation_id": INV,
        "command_kind": _K.RUN,
        "state_before": _C.RUNNING,
        "action": ReconciliationAction.TERMINALIZED_TIMED_OUT,
        "record_after": sample_invocation(_C.TIMED_OUT, kind=_K.RUN),
        "diagnostics": (),
    }
    payload.update(overrides)
    return InvocationReconciliation.model_validate(payload)


def _valid_payload(record: type[CanonicalModel]) -> dict[str, object]:
    payloads: dict[type[CanonicalModel], dict[str, object]] = {
        ExecutableObservation: observation().model_dump(mode="python"),
        LaunchSpecification: {
            "invocation_id": INV,
            "argv": (_EXECUTABLE, "describe"),
            "cwd": _ROOT,
        },
        ProcessInspection: {
            "identity": sample_process_identity(),
            "presence": ProcessPresence.ABSENT,
        },
        LaunchFailure: {
            "stage": "popen",
            "os_error_code": 2,
            "error_class": "FileNotFoundError",
            "not_found": True,
        },
        OutputReadFailure: {"os_error_code": 32, "error_class": "PermissionError"},
        CleanupFailure: {"action": CleanupAction.JOB_CLOSED, "reason": "wait_failed:6"},
        CleanupReport: {"completed": (CleanupAction.JOB_CLOSED,), "failures": ()},
        DescendantIdentity: {"pid": 7, "creation_identity": "windows:7:1"},
        TerminationReport: {
            "forced": False,
            "job_terminated": False,
            "descendants": (),
            "failures": (),
        },
        SupervisionTraceEntry: trace_entry_with().model_dump(mode="python"),
        SupervisionOutcome: outcome_with().model_dump(mode="python"),
        RunReconciliationFacts: facts().model_dump(mode="python"),
        InvocationReconciliation: reconciliation().model_dump(mode="python"),
        ReconciliationReport: {
            "supervisor_instance_id": "supervisor-01",
            "started_at_utc": _INSTANT,
            "entries": (reconciliation(),),
        },
    }
    return payloads[record]


def _module_source() -> str:
    source = models_module.__file__
    assert source is not None
    return Path(source).read_text(encoding="utf-8")


def _annotation_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            names.update(
                n.id for n in ast.walk(node.annotation) if isinstance(n, ast.Name)
            )
    return names


# --------------------------------------------------------------------------
# The plan's Step 1 sketches, verbatim
# --------------------------------------------------------------------------


def test_catalog_launch_arguments_reads_the_metadata_key_and_refuses_other_shapes() -> (
    None
):
    assert catalog_launch_arguments(entry_with({})) == ()
    assert catalog_launch_arguments(
        entry_with({"launch_arguments": ["-I", "-B", "C:\\x\\f.py"]})
    ) == ("-I", "-B", "C:\\x\\f.py")
    for bad in ("text", [""], ["a\x00"], ["x"] * 17):
        with pytest.raises(ValueError, match="launch_arguments"):
            catalog_launch_arguments(entry_with({"launch_arguments": bad}))


def test_creation_identity_round_trips_and_refuses_the_merged_fixture_shapes() -> None:
    text = render_creation_identity(4242, 133_700_000_000_000_000)
    assert text == "windows:4242:133700000000000000"
    assert parse_creation_identity(text) == CreationIdentity(
        4242, 133_700_000_000_000_000
    )
    for bad in (
        "offline-harness:4242",
        "2026-09-07T12:00:03.1234567Z#0001",
        "windows:0:1",
        "windows:1:01",
    ):
        with pytest.raises(ValueError, match="creation identity"):
            parse_creation_identity(bad)


def test_supervision_outcome_requires_parse_kind_agreement_and_a_terminal_record() -> (
    None
):
    with pytest.raises(ValidationError, match="command_kind"):
        outcome_with(
            command_result=exited_run_result(), output_parse=descriptor_parse()
        )


def test_every_retained_record_canonicalises() -> None:
    entry = trace_entry_with(kind=SupervisionTraceKind.LAUNCHED, monotonic_100ns=12_345)
    assert canonical_json_bytes(entry)  # no float anywhere (§11 relies on it)
    assert canonical_json_bytes(outcome_with(trace=(entry,)))
    with pytest.raises(ValidationError, match="repeat"):
        outcome_with(
            trace=(
                trace_entry_with(
                    kind=SupervisionTraceKind.STDOUT_BYTES_COUNTED, sequence=1
                ),
                trace_entry_with(
                    kind=SupervisionTraceKind.STDOUT_BYTES_COUNTED, sequence=2
                ),
            )
        )  # only CLEANUP_ACTION/CLEANUP_FAILED may repeat


# --------------------------------------------------------------------------
# Inventory, shape and field order
# --------------------------------------------------------------------------


def test_the_module_exports_exactly_the_task_two_surface_sorted() -> None:
    exported = models_module.__all__
    assert len(set(exported)) == len(exported)
    # RUF022's isort-style order: SCREAMING_CASE, then CamelCase, then functions.
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    assert set(exported) == {
        *_CONSTANTS,
        "DESCRIBE_STDERR_PLACEHOLDER",
        *(record.__name__ for record in _RECORDS),
        "CreationIdentity",
        "ProcessPresence",
        "InterruptOutcome",
        "CleanupAction",
        "SupervisionTraceKind",
        "ReconciliationAction",
        "catalog_launch_arguments",
        "parse_creation_identity",
        "render_creation_identity",
    }
    assert "OutputReadFailure" in exported


@pytest.mark.parametrize("record", _RECORDS, ids=lambda record: record.__name__)
def test_every_record_is_a_strict_frozen_canonical_model_in_plan_field_order(
    record: type[CanonicalModel],
) -> None:
    assert issubclass(record, CanonicalModel)
    assert record.model_config.get("extra") == "forbid"
    assert record.model_config.get("frozen") is True
    assert record.model_config.get("strict") is True
    assert list(record.model_fields) == _FIELD_ORDER[record]
    assert "schema_version" not in record.model_fields
    built = record.model_validate(_valid_payload(record))
    assert record.model_validate(built.model_dump(mode="python")) == built
    with pytest.raises(ValidationError, match="extra"):
        record.model_validate({**_valid_payload(record), "unexpected": 1})
    with pytest.raises(ValidationError, match="frozen"):
        setattr(built, _FIELD_ORDER[record][0], None)
    assert canonical_json_bytes(built)


def test_no_field_is_annotated_attempt_token_bytes_float_or_a_monotonic_value() -> None:
    tree = ast.parse(_module_source())
    names = _annotation_names(tree)
    for forbidden in (
        "AttemptToken",
        "AttemptTokenMaterial",
        "bytes",
        "float",
        "MonotonicInstant",
        "PairedDeadline",
        "HeartbeatMonitor",
    ):
        assert forbidden not in names, forbidden
    for record in _RECORDS:
        for name, field in record.model_fields.items():
            # A hash of the token is a durable fact; the raw token never is.
            assert not name.endswith("token"), (record.__name__, name)
            assert "environment" not in name, name
            assert not name.startswith("env"), name
            assert field.is_required() or _missing(field.default), name
    assert "environment" not in LaunchSpecification.model_fields
    assert not any(name.startswith("env") for name in LaunchSpecification.model_fields)


def test_the_enums_have_exactly_the_plan_members_in_order() -> None:
    for enum, members in (
        (
            ProcessPresence,
            ["ALIVE_MATCHING", "ALIVE_DIFFERENT_IDENTITY", "ABSENT", "UNDETERMINED"],
        ),
        (InterruptOutcome, ["DELIVERED", "UNAVAILABLE", "PROCESS_GONE"]),
        (CleanupAction, _CLEANUP_ACTIONS),
        (SupervisionTraceKind, _TRACE_KINDS),
        (ReconciliationAction, _RECONCILIATION_ACTIONS),
    ):
        assert issubclass(enum, StrEnum), enum
        assert [member.name for member in enum] == members, enum
        assert all(member.value == member.name for member in enum), enum
    assert len(SupervisionTraceKind) == 28
    assert len(ReconciliationAction) == 11
    assert len(CleanupAction) == 7


# --------------------------------------------------------------------------
# The plan 6.1 constants
# --------------------------------------------------------------------------


def test_the_constants_have_the_plan_values_and_types() -> None:
    for name, expected in _CONSTANTS.items():
        value = getattr(models_module, name)
        assert value == expected, name
        assert type(value) is type(expected), name
    assert LONG_PATH_CEILING == MAX_EXECUTABLE_PATH_CHARACTERS
    assert COMMAND_ROOT_CEILING == DIRECTORY_CEILING_WITHOUT_LONG_PATHS == 247
    assert FILE_CEILING_WITHOUT_LONG_PATHS == 259
    assert FORCED_TERMINATION_EXIT_CODE not in RECOGNIZED_NATIVE_EXIT_VALUES
    assert FORCED_TERMINATION_EXIT_CODE not in {1, 259, 3221225786}
    assert CREATE_SUSPENDED == 4
    assert CTRL_BREAK_EVENT == 1
    assert READ_CHUNK_BYTES * QUEUE_CAPACITY_CHUNKS == 4 * 1024 * 1024
    assert TICK_SECONDS < PIPE_HOLDER_GRACE_SECONDS < POST_TERMINATION_WAIT_SECONDS
    assert READER_JOIN_SECONDS == POST_TERMINATION_WAIT_SECONDS
    assert MAX_LAUNCH_ARGUMENTS == 16
    assert LAUNCH_ARGUMENTS_KEY == "launch_arguments"


def test_the_describe_placeholder_is_nul_bracketed_and_built_at_runtime() -> None:
    assert DESCRIBE_STDERR_PLACEHOLDER == chr(
        0
    ) + "describe-has-no-attempt-token" + chr(0)
    assert DESCRIBE_STDERR_PLACEHOLDER[0] == DESCRIBE_STDERR_PLACEHOLDER[-1] == "\x00"
    source = _module_source()
    assert "\x00" not in source
    (assignment,) = (
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign | ast.AnnAssign)
        and any(
            isinstance(target, ast.Name) and target.id == "DESCRIBE_STDERR_PLACEHOLDER"
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    )
    assert isinstance(assignment.value, ast.BinOp)


# --------------------------------------------------------------------------
# catalog_launch_arguments and the creation identity
# --------------------------------------------------------------------------


def test_catalog_launch_arguments_accepts_the_bounds_and_refuses_null_and_bool() -> (
    None
):
    sixteen = [f"-X{index}" for index in range(16)]
    assert catalog_launch_arguments(entry_with({"launch_arguments": sixteen})) == tuple(
        sixteen
    )
    assert catalog_launch_arguments(entry_with({"launch_arguments": []})) == ()
    assert catalog_launch_arguments(entry_with({"other": ["-I"]})) == ()
    for bad in (None, True, 3, {"a": "b"}, [1], [True], ["ok", " \t"], ["a\x7f"]):
        with pytest.raises(ValueError, match="launch_arguments"):
            catalog_launch_arguments(entry_with({"launch_arguments": bad}))
    with pytest.raises(TypeError, match="AdapterCatalogEntry"):
        catalog_launch_arguments({"launch_arguments": []})  # type: ignore[arg-type]
    spaced = ["-I", "C:\\Program Files\\x y\\f.py"]
    assert catalog_launch_arguments(entry_with({"launch_arguments": spaced})) == tuple(
        spaced
    )


def test_creation_identity_is_a_frozen_dataclass_with_the_plan_bounds() -> None:
    assert is_dataclass(CreationIdentity)
    assert [field.name for field in fields(CreationIdentity)] == [
        "pid",
        "creation_100ns",
    ]
    identity = CreationIdentity(1, 0)
    with pytest.raises(FrozenInstanceError):
        identity.pid = 2  # type: ignore[misc]
    assert CreationIdentity(MAX_PID, 2**63 - 1) == parse_creation_identity(
        f"windows:{MAX_PID}:{2**63 - 1}"
    )
    for pid, creation in ((0, 0), (MAX_PID + 1, 0), (1, -1), (1, 2**63), (True, 0)):
        with pytest.raises(ValueError, match="creation identity"):
            CreationIdentity(pid, creation)
        with pytest.raises(ValueError, match="creation identity"):
            render_creation_identity(pid, creation)
    for bad in (
        f"windows:{MAX_PID + 1}:0",
        f"windows:1:{2**63}",
        "windows:1:1\n",
        " windows:1:1",
        "Windows:1:1",
        "windows:1",
        "windows:1:1:1",
        "windows:-1:1",
        "windows:01:1",
        "",
    ):
        with pytest.raises(ValueError, match="creation identity"):
            parse_creation_identity(bad)
    with pytest.raises(TypeError, match="creation identity"):
        parse_creation_identity(b"windows:1:1")  # type: ignore[arg-type]
    assert render_creation_identity(1, 0) == "windows:1:0"


# --------------------------------------------------------------------------
# Record rules, row by row
# --------------------------------------------------------------------------


def test_executable_observation_holds_a_hash_exactly_for_a_verifiable_file() -> None:
    assert observation().verified is True
    assert observation(observed_hash=_OTHER_HASH).verified is False
    for blocker in (
        {"present": False},
        {"regular_file": False},
        {"reparse_point": True},
        {"ancestor_reparse_point": True},
    ):
        with pytest.raises(ValidationError, match="observed_hash"):
            observation(**blocker)
        unverifiable = observation(**blocker, observed_hash=MISSING)
        assert not isinstance(unverifiable.observed_hash, str)
        assert unverifiable.verified is False
    with pytest.raises(ValidationError, match="observed_hash"):
        observation(observed_hash=MISSING)
    with pytest.raises(ValidationError, match="absolute local"):
        observation(executable_path="adapter.exe")


def test_launch_specification_has_two_or_more_clean_arguments_and_no_environment() -> (
    None
):
    specification = LaunchSpecification(
        invocation_id=INV, argv=(_EXECUTABLE, "-I", "run"), cwd=_ROOT
    )
    assert specification.argv == (_EXECUTABLE, "-I", "run")
    assert "environment" not in LaunchSpecification.model_fields
    with pytest.raises(ValidationError, match="at least 2"):
        LaunchSpecification(invocation_id=INV, argv=(_EXECUTABLE,), cwd=_ROOT)
    for argv, message in (
        (("adapter.exe", "describe"), r"argv\[0\]"),
        ((r"C:\a\..\b.exe", "describe"), r"argv\[0\]"),
        ((_EXECUTABLE, ""), "empty"),
        ((_EXECUTABLE, "a\x00b"), "control character"),
        ((_EXECUTABLE, "describe", "x\x1f"), "control character"),
    ):
        with pytest.raises(ValidationError, match=message):
            LaunchSpecification(invocation_id=INV, argv=argv, cwd=_ROOT)
    with pytest.raises(ValidationError, match="absolute local"):
        LaunchSpecification(invocation_id=INV, argv=(_EXECUTABLE, "run"), cwd="inv")


def test_process_inspection_reports_an_observed_identity_exactly_when_alive() -> None:
    identity = sample_process_identity()
    for presence in (
        ProcessPresence.ALIVE_MATCHING,
        ProcessPresence.ALIVE_DIFFERENT_IDENTITY,
    ):
        alive = ProcessInspection(
            identity=identity,
            presence=presence,
            observed_creation_identity="windows:4321:5",
            observed_image_path=_EXECUTABLE,
        )
        assert alive.observed_creation_identity == "windows:4321:5"
        ProcessInspection(
            identity=identity, presence=presence, observed_creation_identity="w"
        )
        with pytest.raises(ValidationError, match="observed_creation_identity"):
            ProcessInspection(identity=identity, presence=presence)
    for presence in (ProcessPresence.ABSENT, ProcessPresence.UNDETERMINED):
        gone = ProcessInspection(identity=identity, presence=presence)
        assert not isinstance(gone.observed_creation_identity, str)
        with pytest.raises(ValidationError, match="observed_creation_identity"):
            ProcessInspection(
                identity=identity,
                presence=presence,
                observed_creation_identity="windows:4321:5",
            )
        with pytest.raises(ValidationError, match="observed_image_path"):
            ProcessInspection(
                identity=identity, presence=presence, observed_image_path=_EXECUTABLE
            )
    assert "timestamp" not in "".join(ProcessInspection.model_fields)


def test_launch_failure_not_found_is_winerror_two_or_three_at_popen() -> None:
    for code in (2, 3):
        failure = LaunchFailure(
            stage="popen",
            os_error_code=code,
            error_class="FileNotFoundError",
            not_found=True,
        )
        assert failure.not_found is True
        with pytest.raises(ValidationError, match="not_found"):
            LaunchFailure(
                stage="popen",
                os_error_code=code,
                error_class="OSError",
                not_found=False,
            )
    LaunchFailure(
        stage="popen", os_error_code=5, error_class="PermissionError", not_found=False
    )
    LaunchFailure(stage="popen", error_class="OSError", not_found=False)
    for stage in ("open_process", "resume"):
        LaunchFailure(
            stage=stage, os_error_code=2, error_class="OpenProcess", not_found=False
        )
        with pytest.raises(ValidationError, match="not_found"):
            LaunchFailure(
                stage=stage, os_error_code=2, error_class="OpenProcess", not_found=True
            )
    with pytest.raises(ValidationError, match="not_found"):
        LaunchFailure(stage="popen", error_class="OSError", not_found=True)
    with pytest.raises(ValidationError, match="stage"):
        LaunchFailure(
            stage="create_root",  # type: ignore[arg-type]
            os_error_code=5,
            error_class="OSError",
            not_found=False,
        )
    with pytest.raises(ValidationError, match="error_class"):
        LaunchFailure(stage="popen", os_error_code=5, error_class="", not_found=False)


def test_output_read_failure_is_the_plan_7_4_two_field_record() -> None:
    """Plan 7.4: what ``read_output_file`` (Task 3) returns for a file that exists but
    cannot be read; the supervisor derives ``output_unreadable`` from it and mints no
    diagnostic. It carries a bounded class name and an optional error number only."""
    denied = OutputReadFailure(os_error_code=32, error_class="PermissionError")
    assert (denied.os_error_code, denied.error_class) == (32, "PermissionError")
    unnumbered = OutputReadFailure(error_class="OSError")
    assert not isinstance(unnumbered.os_error_code, int)
    assert unnumbered.model_dump(mode="json") == {"error_class": "OSError"}
    assert list(OutputReadFailure.model_fields) == ["os_error_code", "error_class"]
    with pytest.raises(ValidationError, match="error_class"):
        OutputReadFailure(os_error_code=32, error_class="")
    with pytest.raises(ValidationError, match="error_class"):
        OutputReadFailure(os_error_code=32, error_class="x" * 1025)
    with pytest.raises(ValidationError, match="os_error_code"):
        OutputReadFailure(os_error_code="32", error_class="OSError")
    with pytest.raises(ValidationError, match="os_error_code"):
        OutputReadFailure(os_error_code=True, error_class="OSError")
    with pytest.raises(ValidationError, match="extra"):
        OutputReadFailure.model_validate(
            {"os_error_code": 32, "error_class": "OSError", "path": r"C:\x\output.json"}
        )
    with pytest.raises(ValidationError, match="extra"):
        OutputReadFailure.model_validate(
            {"os_error_code": 32, "error_class": "OSError", "partial_bytes": "x"}
        )
    assert (
        canonical_json_bytes(denied)
        == b'{"error_class":"PermissionError","os_error_code":32}'
    )
    assert "bytes" not in "".join(OutputReadFailure.model_fields)


def test_cleanup_report_is_unique_disjoint_and_complete_without_failures() -> None:
    report = CleanupReport(
        completed=(CleanupAction.STDOUT_READER_STOPPED, CleanupAction.JOB_CLOSED),
        failures=(cleanup_failure(CleanupAction.PIPES_CLOSED),),
    )
    assert report.complete is False
    assert CleanupReport(completed=(), failures=()).complete is True
    assert CleanupReport(completed=tuple(CleanupAction), failures=()).complete is True
    with pytest.raises(ValidationError, match="unique"):
        CleanupReport(
            completed=(CleanupAction.JOB_CLOSED, CleanupAction.JOB_CLOSED), failures=()
        )
    with pytest.raises(ValidationError, match="unique"):
        CleanupReport(
            completed=(),
            failures=(cleanup_failure(), cleanup_failure()),
        )
    with pytest.raises(ValidationError, match="disjoint"):
        CleanupReport(
            completed=(CleanupAction.JOB_CLOSED,), failures=(cleanup_failure(),)
        )
    with pytest.raises(ValidationError, match="reason"):
        CleanupFailure(action=CleanupAction.JOB_CLOSED, reason="")
    with pytest.raises(ValidationError, match="action"):
        CleanupFailure(action="JOB_CLOSED", reason="x")  # type: ignore[arg-type]


def test_termination_report_carries_the_exit_code_exactly_when_forced() -> None:
    descendant = DescendantIdentity(pid=9, creation_identity="windows:9:2")
    forced = TerminationReport(
        forced=True,
        exit_code_used=FORCED_TERMINATION_EXIT_CODE,
        job_terminated=True,
        descendants=(descendant,),
        failures=(cleanup_failure(CleanupAction.TREE_VERIFIED_DEAD),),
    )
    assert forced.exit_code_used == 1067
    assert not isinstance(descendant.image_path, str)
    gentle = TerminationReport(
        forced=False, job_terminated=False, descendants=(), failures=()
    )
    assert not isinstance(gentle.exit_code_used, int)
    with pytest.raises(ValidationError, match="exit_code_used"):
        TerminationReport(
            forced=True, job_terminated=False, descendants=(), failures=()
        )
    with pytest.raises(ValidationError, match="exit_code_used"):
        TerminationReport(
            forced=False,
            exit_code_used=1067,
            job_terminated=False,
            descendants=(),
            failures=(),
        )
    for pid in (0, MAX_PID + 1):
        with pytest.raises(ValidationError, match="pid"):
            DescendantIdentity(pid=pid, creation_identity="windows:9:2")
    # A verified tree may report several TREE_VERIFIED_DEAD survivors (plan 8.3).
    TerminationReport(
        forced=True,
        exit_code_used=1067,
        job_terminated=False,
        descendants=(),
        failures=(
            cleanup_failure(CleanupAction.TREE_VERIFIED_DEAD),
            cleanup_failure(CleanupAction.TREE_VERIFIED_DEAD),
        ),
    )


def test_a_trace_entry_carries_a_rejection_exactly_on_event_rejected() -> None:
    rejected = trace_entry_with(
        kind=SupervisionTraceKind.EVENT_REJECTED, rejection=rejection()
    )
    assert isinstance(rejected.rejection, EventRejected)
    with pytest.raises(ValidationError, match="rejection"):
        trace_entry_with(kind=SupervisionTraceKind.EVENT_REJECTED)
    with pytest.raises(ValidationError, match="rejection"):
        trace_entry_with(kind=SupervisionTraceKind.LAUNCHED, rejection=rejection())
    with pytest.raises(ValidationError, match="greater than or equal to 1"):
        trace_entry_with(sequence=0)
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        trace_entry_with(monotonic_100ns=-1)
    with pytest.raises(ValidationError, match="monotonic_100ns"):
        trace_entry_with(monotonic_100ns=1.5)
    with pytest.raises(ValidationError, match="monotonic_100ns"):
        trace_entry_with(monotonic_100ns=True)


def test_trace_facts_take_the_diagnostic_detail_bounds() -> None:
    entry = trace_entry_with(
        kind=SupervisionTraceKind.EXIT_REAPED,
        facts={"native_exit_value": 0, "output_unreadable": False, "state": "EXITED"},
    )
    assert entry.facts == {
        "native_exit_value": 0,
        "output_unreadable": False,
        "state": "EXITED",
    }
    for bad in (
        {"attempt_token": "x"},
        {"ratio": 0.5},
        {"count": 2**63},
        {"k": list(range(65))},
        {"payload": ["x" * 2_048 for _ in range(8)]},
        {f"key{index}": index for index in range(65)},
        {"groups": [{f"key{index}": index for index in range(64)} for _ in range(4)]},
    ):
        with pytest.raises(ValidationError, match="facts"):
            trace_entry_with(facts=bad)


def test_supervision_outcome_couples_integrity_to_the_decided_state() -> None:
    for state, kind in (
        (_C.PROTOCOL_FAILED, _K.RUN),
        (_C.PROTOCOL_FAILED, _K.VALIDATE),
    ):
        violated = outcome_with(command_result=result_for(state, kind))
        assert violated.command_result.protocol_integrity is (
            ProtocolIntegrityStatus.VIOLATED
        )
    exited_but_violated = exited_run_result(
        protocol_integrity=ProtocolIntegrityStatus.VIOLATED
    )
    with pytest.raises(ValidationError, match="protocol_integrity"):
        outcome_with(command_result=exited_but_violated)
    for state in (_C.CANCELLED, _C.TIMED_OUT, _C.FAILED_TO_START):
        outcome = outcome_with(command_result=result_for(state, _K.RUN))
        assert outcome.command_result.cancelled is (state is _C.CANCELLED)
        assert outcome.command_result.timed_out is (state is _C.TIMED_OUT)
    with pytest.raises(ValidationError, match="terminal"):
        exited_run_result(invocation=sample_invocation(_C.RUNNING, kind=_K.RUN))


def test_output_parse_is_present_only_for_exited_and_matches_the_kind() -> None:
    for kind, parse in (
        (_K.DESCRIBE, failed_descriptor_parse()),
        (_K.VALIDATE, failed_validation_parse()),
        (_K.RUN, failed_manifest_parse()),
    ):
        outcome = outcome_with(
            command_result=result_for(_C.EXITED, kind), output_parse=parse
        )
        assert outcome.output_parse == parse
        assert not isinstance(outcome.command_result.parsed_output, CanonicalModel)
        for other in (
            failed_descriptor_parse(),
            failed_validation_parse(),
            failed_manifest_parse(),
        ):
            if type(other) is type(parse):
                continue
            with pytest.raises(ValidationError, match="command_kind"):
                outcome_with(
                    command_result=result_for(_C.EXITED, kind), output_parse=other
                )
        with pytest.raises(ValidationError, match="EXITED"):
            outcome_with(
                command_result=result_for(_C.CANCELLED, kind), output_parse=parse
            )
    absent = outcome_with(command_result=result_for(_C.EXITED, _K.DESCRIBE))
    assert not isinstance(absent.output_parse, CanonicalModel)


def test_parsed_output_is_present_exactly_when_the_parse_holds_its_model() -> None:
    parse = descriptor_parse()
    assert isinstance(parse.envelope, BootstrapDescriptorEnvelope)
    described = outcome_with(
        command_result=result_for(
            _C.EXITED,
            _K.DESCRIBE,
            parsed_output=parse.envelope,
            parsed_output_source_hash=parse.source_hash,
        ),
        output_parse=parse,
    )
    assert described.command_result.parsed_output == parse.envelope
    with pytest.raises(ValidationError, match="parsed_output"):
        outcome_with(
            command_result=result_for(_C.EXITED, _K.DESCRIBE), output_parse=parse
        )
    with pytest.raises(ValidationError, match="source_hash"):
        outcome_with(
            command_result=result_for(
                _C.EXITED,
                _K.DESCRIBE,
                parsed_output=parse.envelope,
                parsed_output_source_hash=_OTHER_HASH,
            ),
            output_parse=parse,
        )
    with pytest.raises(ValidationError, match="parsed_output"):
        outcome_with(
            command_result=result_for(
                _C.EXITED,
                _K.DESCRIBE,
                parsed_output=parse.envelope,
                parsed_output_source_hash=parse.source_hash,
            )
        )
    with pytest.raises(ValidationError, match="parsed_output"):
        outcome_with(
            command_result=result_for(
                _C.EXITED,
                _K.DESCRIBE,
                parsed_output=parse.envelope,
                parsed_output_source_hash=parse.source_hash,
            ),
            output_parse=failed_descriptor_parse(),
        )


def test_parsed_output_couples_a_validation_result_and_its_source_hash() -> None:
    """The VALIDATE branch of the coupling rule with a real strict result, so the
    dispatch on the parse class is pinned beyond the describe envelope."""
    parse = validation_parse()
    assert isinstance(parse.result, AdapterValidationResult)
    validated = outcome_with(
        command_result=result_for(
            _C.EXITED,
            _K.VALIDATE,
            parsed_output=parse.result,
            parsed_output_source_hash=parse.source_hash,
        ),
        output_parse=parse,
    )
    assert validated.command_result.parsed_output == parse.result
    assert validated.command_result.parsed_output_source_hash == parse.source_hash
    with pytest.raises(ValidationError, match="parsed_output"):
        outcome_with(
            command_result=result_for(_C.EXITED, _K.VALIDATE), output_parse=parse
        )
    with pytest.raises(ValidationError, match="source_hash"):
        outcome_with(
            command_result=result_for(
                _C.EXITED,
                _K.VALIDATE,
                parsed_output=parse.result,
                parsed_output_source_hash=_OTHER_HASH,
            ),
            output_parse=parse,
        )
    with pytest.raises(ValidationError, match="command_kind"):
        outcome_with(command_result=result_for(_C.EXITED, _K.RUN), output_parse=parse)


def test_the_summary_agrees_with_the_accepted_events_and_is_empty_for_describe() -> (
    None
):
    with pytest.raises(ValidationError, match="accepted_count"):
        outcome_with(protocol_summary=empty_summary(accepted_count=1, last_sequence=1))
    describe = result_for(_C.EXITED, _K.DESCRIBE)
    counted = outcome_with(command_result=describe, stdout_byte_count=17)
    assert counted.stdout_byte_count == 17
    with pytest.raises(ValidationError, match="DESCRIBE"):
        outcome_with(
            command_result=describe, protocol_summary=empty_summary(redactions=1)
        )
    with pytest.raises(ValidationError, match="stdout_byte_count"):
        outcome_with(stdout_byte_count=1)
    with pytest.raises(ValidationError, match="stdout_byte_count"):
        outcome_with(
            command_result=result_for(_C.EXITED, _K.VALIDATE), stdout_byte_count=1
        )
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        outcome_with(replay_count=-1)
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        outcome_with(command_result=describe, stdout_byte_count=-1)


def test_the_retained_trace_names_the_invocation_in_order_without_per_event_kinds() -> (
    None
):
    entries = (
        trace_entry_with(kind=SupervisionTraceKind.LAUNCHED, sequence=3),
        trace_entry_with(
            kind=SupervisionTraceKind.EVENT_REJECTED, sequence=7, rejection=rejection()
        ),
        trace_entry_with(kind=SupervisionTraceKind.CLEANUP_ACTION, sequence=9),
        trace_entry_with(kind=SupervisionTraceKind.CLEANUP_ACTION, sequence=10),
        trace_entry_with(kind=SupervisionTraceKind.CLEANUP_FAILED, sequence=11),
        trace_entry_with(kind=SupervisionTraceKind.CLEANUP_FAILED, sequence=12),
    )
    outcome = outcome_with(trace=entries)
    assert [entry.sequence for entry in outcome.trace] == [3, 7, 9, 10, 11, 12]
    with pytest.raises(ValidationError, match="name the invocation"):
        outcome_with(trace=(trace_entry_with(invocation_id=_OTHER_INV),))
    with pytest.raises(ValidationError, match="sequence"):
        outcome_with(trace=(entries[1], entries[0]))
    with pytest.raises(ValidationError, match="sequence"):
        outcome_with(
            trace=(
                entries[0],
                trace_entry_with(sequence=3, kind=SupervisionTraceKind.EXIT_REAPED),
            )
        )
    for kind in (
        SupervisionTraceKind.EVENT_ACCEPTED,
        SupervisionTraceKind.EVENT_REPLAYED,
    ):
        with pytest.raises(ValidationError, match="never retained"):
            outcome_with(trace=(trace_entry_with(kind=kind),))
    with pytest.raises(ValidationError, match="repeat"):
        outcome_with(
            trace=(
                trace_entry_with(
                    kind=SupervisionTraceKind.FORCED_TERMINATION, sequence=1
                ),
                trace_entry_with(
                    kind=SupervisionTraceKind.FORCED_TERMINATION, sequence=2
                ),
            )
        )
    with pytest.raises(ValidationError, match="repeat"):
        outcome_with(
            trace=(
                entries[1],
                trace_entry_with(
                    kind=SupervisionTraceKind.EVENT_REJECTED,
                    sequence=8,
                    rejection=rejection(),
                ),
            )
        )


def test_run_reconciliation_facts_are_cancelled_by_run_or_experiment() -> None:
    assert facts().cancelled is False
    assert facts(run_state=EngineRunState.CANCELLED).cancelled is True
    assert facts(experiment_state=ExperimentState.CANCELLED).cancelled is True
    assert (
        facts(
            run_state=EngineRunState.TIMED_OUT, experiment_state=ExperimentState.FAILED
        ).cancelled
        is False
    )
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        facts(run_revision=-1)
    with pytest.raises(ValidationError, match="attempt_token_hash"):
        facts(attempt_token_hash="A" * 32)


def test_invocation_reconciliation_reports_a_manifest_only_when_left_running() -> None:
    left = reconciliation(
        state_before=_C.RUNNING,
        action=ReconciliationAction.LEFT_RUNNING_AWAITING_DEADLINE,
        record_after=sample_invocation(_C.RUNNING, kind=_K.RUN),
        presence=ProcessPresence.ABSENT,
        manifest_present=False,
    )
    assert left.manifest_present is False
    assert left.presence is ProcessPresence.ABSENT
    with pytest.raises(ValidationError, match="manifest_present"):
        reconciliation(
            action=ReconciliationAction.LEFT_RUNNING_AWAITING_DEADLINE,
            record_after=sample_invocation(_C.RUNNING, kind=_K.RUN),
        )
    with pytest.raises(ValidationError, match="manifest_present"):
        reconciliation(manifest_present=True)
    with pytest.raises(ValidationError, match="manifest_present"):
        reconciliation(
            command_kind=_K.VALIDATE,
            action=ReconciliationAction.LEFT_RUNNING_AWAITING_DEADLINE,
            record_after=sample_invocation(_C.RUNNING, kind=_K.VALIDATE),
            manifest_present=False,
        )
    with pytest.raises(ValidationError, match="invocation_id"):
        reconciliation(invocation_id=_OTHER_INV)
    with pytest.raises(ValidationError, match="command_kind"):
        reconciliation(command_kind=_K.VALIDATE)
    uninspected = reconciliation()
    assert not isinstance(uninspected.presence, ProcessPresence)
    assert not isinstance(uninspected.manifest_present, bool)
    duplicate = rejection().diagnostic
    with pytest.raises(ValidationError, match="unique"):
        reconciliation(diagnostics=(duplicate, duplicate))


def test_a_reconciliation_report_lists_each_invocation_once_in_source_order() -> None:
    first = reconciliation()
    second = reconciliation(
        invocation_id=_OTHER_INV,
        record_after=sample_invocation(
            _C.TIMED_OUT, kind=_K.RUN, invocation_id=_OTHER_INV
        ),
    )
    report = ReconciliationReport(
        supervisor_instance_id="supervisor-01",
        started_at_utc=_INSTANT,
        entries=(second, first),
    )
    assert [entry.invocation_id for entry in report.entries] == [_OTHER_INV, INV]
    with pytest.raises(ValidationError, match="unique"):
        ReconciliationReport(
            supervisor_instance_id="supervisor-01",
            started_at_utc=_INSTANT,
            entries=(first, first),
        )
    with pytest.raises(ValidationError, match="started_at_utc"):
        ReconciliationReport(
            supervisor_instance_id="supervisor-01",
            started_at_utc=(_INSTANT + timedelta(hours=1)).replace(tzinfo=None),
            entries=(),
        )


# --------------------------------------------------------------------------
# Purity: no clock, no process, the reviewed import closure
# --------------------------------------------------------------------------


def test_the_module_reads_no_clock_and_imports_only_domain_and_adapters() -> None:
    text = _module_source()
    for forbidden in (
        "datetime.now",
        "utcnow",
        "time.time",
        "now_utc(",
        "monotonic(",
        "import time",
        "import random",
        "random.",
        "uuid4(",
        "os.environ",
        "import os",
        "import subprocess",
        "import threading",
        "import ctypes",
        "import asyncio",
        "import queue",
        "import doubles",
        "from doubles",
    ):
        assert forbidden not in text, forbidden
    tree = ast.parse(text)
    roots: set[str] = set()
    project: set[str] = set()
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
        for module in modules:
            roots.add(module.partition(".")[0])
            if module.startswith("crypto_lab"):
                project.add(module)
    assert roots <= _PURE_ROOTS, roots - _PURE_ROOTS
    for module in project:
        assert module.startswith(("crypto_lab.domain.", "crypto_lab.adapters.")), module
    assert "crypto_lab.adapters.commands" in project
    assert "crypto_lab.domain.command_invocation" in project
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert identifiers.isdisjoint(_STAGE4_BARE_NAMES)
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    for later in (
        "ProcessSupervisor",
        "RunManifest",
        "ArtifactRef",
        "AuditEvent",
        "AuditSink",
    ):
        assert later not in defined
