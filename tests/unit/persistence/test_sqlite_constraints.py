"""The raw-statement half of C-27: every trigger and state CHECK fires (plan 3.3, 3.4).

Plan Task 2 Step 1. ``SEED_STATEMENTS`` holds shape-valid literal rows, one per
table in the plan 6.4 dependency order (plus the extra ``experiments``,
``engine_runs`` and ``command_invocations`` rows the trigger cases need: a
``QUEUED`` experiment with a frozen snapshot, a terminal one, a ``VALIDATED`` one
without a snapshot and a ``DRAFT`` one; a terminal and a pending run; a terminal,
a pending and a ``DESCRIBE`` invocation), executed through ``raw_connection`` by
the ``seeded_database`` fixture because no codec exists before Task 3. Every
statement below is a literal with bound parameters, never text composed from a
row value. ``TERMINAL_STATE_CHANGE_STATEMENTS`` are the refusals: a raw
``UPDATE`` that changes a terminal state, a frozen spec, a frozen or cleared
snapshot, the queue edge without a snapshot; a raw ``DELETE`` on every append-only
table and on the three never-deleted tables; a row violating each 15.2 state
CHECK, the run shapes, the decision outcomes and the owner variants; a partially
filled snapshot; a ``diagnostic_causes`` self-edge; the composite foreign keys;
the two partial unique indexes. Task 4 adds the repository half. The positive
controls prove the permitted writes still pass, so the CHECKs are not stricter
than the record validators they mirror.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from sqlalchemy.exc import IntegrityError

from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from doubles.experiments import (
    AVAIL_A,
    AVAIL_B,
    DATASET_HASH,
    DIAG_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    MATERIAL_HASH,
    OTHER_DIAG_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    SLOT_B,
    STRATEGY_HASH,
    THIRD_RUN_ID,
    UUID_A,
    UUID_C,
    UUID_D,
    UUID_E,
)

type Statement = tuple[str, tuple[object, ...]]

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


def _micros(instant: datetime) -> int:
    return (instant - _EPOCH) // timedelta(microseconds=1)


def _uuid(index: int) -> str:
    """A deterministic UUID4-shaped suffix for the extra identities."""
    return f"{index:08x}-0000-4000-8000-{index:012x}"


T0: Final = _micros(INSTANT)
SECOND: Final = 1_000_000
HOUR: Final = 3_600 * SECOND
EXP_C: Final = f"exp_{UUID_C}"
EXP_D: Final = f"exp_{UUID_D}"
EXP_E: Final = f"exp_{UUID_E}"
INV_C: Final = f"inv_{UUID_C}"
EVT_A: Final = f"evt_{UUID_A}"
STRV_A: Final = f"strv_{UUID_A}"
STRAT_A: Final = f"strat_{UUID_A}"
DS_A: Final = f"ds_{UUID_A}"
PART_A: Final = f"part_{UUID_A}"
SPEC_HASH: Final = "a" * 64
AUDIT_HASH: Final = "d" * 64
TOKEN_HASH: Final = "7" * 64
EXECUTABLE_HASH: Final = "e" * 64
CONTENT_HASH: Final = "f" * 64
OWNER_HASH: Final = "0" * 63 + "1"
EXECUTABLE_PATH: Final = "C:\\adapters\\alpha\\adapter.exe"
_TERMINAL_INVOCATION_STATES: Final = frozenset(
    {"EXITED", "FAILED_TO_START", "CANCELLED", "TIMED_OUT", "PROTOCOL_FAILED"}
)

# --------------------------------------------------------------------------
# Row builders: a valid row by default, one field overridden per refusal
# --------------------------------------------------------------------------

_EXPERIMENT_SQL: Final = (
    "INSERT INTO experiments (experiment_id, schema_version, state, spec, spec_hash,"
    " strategy_version_hash, dataset_version_hash, slot_compatibility,"
    " cancellation_correlation_id, created_at_utc, updated_at_utc, revision,"
    " configuration_snapshot_schema_version, configuration_snapshot_json,"
    " configuration_audit_hash, material_base_configuration_hash)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def experiment_row(
    experiment_id: str,
    state: str,
    *,
    schema_version: str = "1.0.0",
    spec_hash: str = SPEC_HASH,
    slot_compatibility: str | None = None,
    cancellation_correlation_id: str | None = None,
    created_at_utc: int = T0,
    updated_at_utc: int = T0,
    revision: int = 0,
    snapshot: bool = False,
    snapshot_schema_version: str | None = None,
    snapshot_json: str | None = None,
    audit_hash: str | None = None,
    material_hash: str | None = None,
) -> Statement:
    if snapshot:
        snapshot_schema_version = snapshot_schema_version or "1.0.0"
        snapshot_json = snapshot_json or "{}"
        audit_hash = audit_hash or AUDIT_HASH
        material_hash = material_hash or MATERIAL_HASH
    return (
        _EXPERIMENT_SQL,
        (
            experiment_id,
            schema_version,
            state,
            "{}",
            spec_hash,
            STRATEGY_HASH,
            DATASET_HASH,
            slot_compatibility,
            cancellation_correlation_id,
            created_at_utc,
            updated_at_utc,
            revision,
            snapshot_schema_version,
            snapshot_json,
            audit_hash,
            material_hash,
        ),
    )


_SLOT_SQL: Final = (
    "INSERT INTO engine_slots (experiment_id, logical_slot_id, slot_ordinal,"
    " adapter_name, adapter_version, engine_name, engine_version)"
    " VALUES (?, ?, ?, ?, ?, ?, ?)"
)


def slot_row(
    experiment_id: str,
    logical_slot_id: str,
    slot_ordinal: int,
    *,
    adapter: tuple[str, str] = ("adapter.alpha", "1.0.0"),
    engine: tuple[str, str] = ("engine.alpha", "2.3.4"),
) -> Statement:
    return (
        _SLOT_SQL,
        (experiment_id, logical_slot_id, slot_ordinal, *adapter, *engine),
    )


_OBSERVATION_SQL: Final = (
    "INSERT INTO runtime_availability_observations (availability_observation_id,"
    " schema_version, adapter_name, adapter_version, executable_path,"
    " executable_hash, runtime_version, operating_system, available, reason_code,"
    " observed_at_utc, expires_at_utc, network_required, credentials_required,"
    " content_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def observation_row(
    observation_id: str,
    *,
    operating_system: str = "WINDOWS",
    available: int = 1,
    reason_code: str | None = None,
    observed_at_utc: int = T0,
    expires_at_utc: int = T0 + HOUR,
) -> Statement:
    return (
        _OBSERVATION_SQL,
        (
            observation_id,
            "1.0.0",
            "adapter.alpha",
            "1.0.0",
            EXECUTABLE_PATH,
            EXECUTABLE_HASH,
            "3.12.0",
            operating_system,
            available,
            reason_code,
            observed_at_utc,
            expires_at_utc,
            0,
            0,
            CONTENT_HASH,
        ),
    )


_DIAGNOSTIC_SQL: Final = (
    "INSERT INTO diagnostics (diagnostic_id, schema_version, severity, error_code,"
    " category, message, source_component, experiment_id, run_id, invocation_id,"
    " engine, retriable, timestamp_utc, details, causal_diagnostic_ids)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def diagnostic_row(
    diagnostic_id: str,
    *,
    severity: str = "ERROR",
    error_code: str = "PERSISTENCE.WRITE_FAILED",
    category: str = "PERSISTENCE",
    message: str = "a recorded fact",
    experiment_id: str | None = None,
    run_id: str | None = None,
    invocation_id: str | None = None,
    details: str = "{}",
    causal_diagnostic_ids: str = "[]",
) -> Statement:
    return (
        _DIAGNOSTIC_SQL,
        (
            diagnostic_id,
            "1.0.0",
            severity,
            error_code,
            category,
            message,
            "persistence",
            experiment_id,
            run_id,
            invocation_id,
            None,
            0,
            T0,
            details,
            causal_diagnostic_ids,
        ),
    )


_STRATEGY_VERSION_SQL: Final = (
    "INSERT INTO strategy_versions (content_hash, strategy_version_id, strategy_id,"
    " schema_version, record, hashing_profile_version, created_at_utc)"
    " VALUES (?, ?, ?, ?, ?, ?, ?)"
)


def strategy_version_row(
    content_hash: str = STRATEGY_HASH,
    strategy_version_id: str = STRV_A,
    *,
    strategy_id: str = STRAT_A,
    hashing_profile_version: str = "strategy-version/v1",
    created_at_utc: int = T0,
) -> Statement:
    return (
        _STRATEGY_VERSION_SQL,
        (
            content_hash,
            strategy_version_id,
            strategy_id,
            "1.0.0",
            "{}",
            hashing_profile_version,
            created_at_utc,
        ),
    )


_DATASET_SQL: Final = (
    "INSERT INTO datasets (dataset_id, content_hash, schema_version, record, venue,"
    " instrument_canonical_id, data_type, timeframe, start_utc, end_utc,"
    " validation_status, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def dataset_row(
    dataset_id: str = DS_A,
    content_hash: str = DATASET_HASH,
    *,
    data_type: str = "OHLCV",
    timeframe: str | None = "1m",
    start_utc: int = T0 - 24 * HOUR,
    end_utc: int = T0,
) -> Statement:
    return (
        _DATASET_SQL,
        (
            dataset_id,
            content_hash,
            "1.0.0",
            "{}",
            "BINANCE",
            "BINANCE:BTC-USDT:SPOT",
            data_type,
            timeframe,
            start_utc,
            end_utc,
            "VALID",
            T0,
        ),
    )


_PARTITION_SQL: Final = (
    "INSERT INTO dataset_partitions (partition_id, dataset_id, ordinal, record,"
    " content_hash, raw_checksum, normalized_checksum, relative_path, row_count,"
    " start_utc, end_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def partition_row(
    partition_id: str = PART_A,
    *,
    dataset_id: str = DS_A,
    ordinal: int = 0,
    content_hash: str = "3" * 64,
    start_utc: int = T0 - 24 * HOUR,
    end_utc: int = T0,
) -> Statement:
    return (
        _PARTITION_SQL,
        (
            partition_id,
            dataset_id,
            ordinal,
            "{}",
            content_hash,
            "4" * 64,
            "5" * 64,
            "ds/part-0.parquet",
            10,
            start_utc,
            end_utc,
        ),
    )


_RUN_SQL: Final = (
    "INSERT INTO engine_runs (run_id, schema_version, experiment_id, logical_slot_id,"
    " attempt_number, attempt_token_hash, state, adapter_name, adapter_version,"
    " engine_name, engine_version, request_hash, predecessor_run_id, retry_reason,"
    " primary_terminal_diagnostic_id, availability_observation_id, created_at_utc,"
    " updated_at_utc, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
    " ?, ?, ?)"
)


def run_row(
    run_id: str,
    state: str,
    *,
    experiment_id: str = EXPERIMENT_ID,
    logical_slot_id: str = SLOT_A,
    attempt_number: int = 1,
    predecessor_run_id: str | None = None,
    retry_reason: str | None = None,
    primary_terminal_diagnostic_id: str | None = None,
    availability_observation_id: str | None = None,
    created_at_utc: int = T0,
    updated_at_utc: int = T0,
    revision: int = 0,
) -> Statement:
    return (
        _RUN_SQL,
        (
            run_id,
            "1.0.0",
            experiment_id,
            logical_slot_id,
            attempt_number,
            TOKEN_HASH,
            state,
            "adapter.alpha",
            "1.0.0",
            "engine.alpha",
            "2.3.4",
            REQUEST_HASH,
            predecessor_run_id,
            retry_reason,
            primary_terminal_diagnostic_id,
            availability_observation_id,
            created_at_utc,
            updated_at_utc,
            revision,
        ),
    )


_INVOCATION_SQL: Final = (
    "INSERT INTO command_invocations (invocation_id, schema_version, command_kind,"
    " adapter_name, adapter_version, run_id, request_hash, timeout_seconds, state,"
    " process_created, launch_attempted_at_utc, deadline_utc, process_started_at_utc,"
    " pid, creation_identity, executable_path, executable_hash,"
    " supervisor_instance_id, completed_at_utc, native_exit_value,"
    " process_exit_category, cleanup_complete, cleanup_completed_at_utc,"
    " stderr_artifact_id, primary_diagnostic_id, diagnostic_ids, created_at_utc,"
    " updated_at_utc, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
    " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def invocation_row(
    invocation_id: str,
    state: str,
    *,
    command_kind: str = "RUN",
    run_id: str | None = RUN_ID,
    timeout_seconds: int = 60,
    process_created: int | None = None,
    launched: bool | None = None,
    launch_attempted_at_utc: int | None = None,
    deadline_utc: int | None = None,
    process: bool | None = None,
    pid: int | None = None,
    creation_identity: str | None = None,
    executable_path: str | None = None,
    executable_hash: str | None = None,
    supervisor_instance_id: str | None = None,
    process_started_at_utc: int | None = None,
    completed_at_utc: int | None = None,
    completed: bool | None = None,
    native_exit_value: int | None = None,
    process_exit_category: str | None = None,
    cleanup_complete: int = 0,
    cleanup_completed_at_utc: int | None = None,
    stderr_artifact_id: str | None = None,
    primary_diagnostic_id: str | None = None,
    diagnostic_ids: str = "[]",
    created_at_utc: int = T0,
    updated_at_utc: int = T0,
    revision: int = 0,
    terminal_defaults: bool = True,
) -> Statement:
    """A shape-valid row for ``state`` unless a keyword overrides one field.

    ``launched`` fills ``launch_attempted_at_utc``/``deadline_utc`` consistently,
    ``process`` fills the six process columns, ``completed`` fills
    ``completed_at_utc``; each defaults to the state's own shape.
    ``terminal_defaults`` fills the native exit of ``EXITED`` and the primary
    diagnostic of the four other terminals; a refusal row switches it off.
    """
    terminal = state in _TERMINAL_INVOCATION_STATES
    if launched is None:
        launched = state != "PENDING"
    if launched:
        launch_attempted_at_utc = (
            T0 if launch_attempted_at_utc is None else launch_attempted_at_utc
        )
        if deadline_utc is None:
            deadline_utc = launch_attempted_at_utc + timeout_seconds * SECOND
    if process is None:
        process = state in {"RUNNING", "EXITED", "PROTOCOL_FAILED"}
    if process_created is None:
        process_created = 1 if process else 0
    if process:
        pid = 4242 if pid is None else pid
        creation_identity = creation_identity or "creation-1"
        executable_path = executable_path or EXECUTABLE_PATH
        executable_hash = executable_hash or EXECUTABLE_HASH
        supervisor_instance_id = supervisor_instance_id or "supervisor-1"
        process_started_at_utc = (
            T0 if process_started_at_utc is None else process_started_at_utc
        )
    if completed is None:
        completed = terminal
    if completed and completed_at_utc is None:
        completed_at_utc = T0
    if (
        terminal_defaults
        and state == "EXITED"
        and native_exit_value is None
        and process_exit_category is None
    ):
        native_exit_value, process_exit_category = 0, "SUCCESS"
    if (
        terminal_defaults
        and state in {"FAILED_TO_START", "CANCELLED", "TIMED_OUT", "PROTOCOL_FAILED"}
        and primary_diagnostic_id is None
    ):
        primary_diagnostic_id = DIAG_ID
        diagnostic_ids = json.dumps([DIAG_ID])
    return (
        _INVOCATION_SQL,
        (
            invocation_id,
            "1.0.0",
            command_kind,
            "adapter.alpha",
            "1.0.0",
            run_id,
            REQUEST_HASH,
            timeout_seconds,
            state,
            process_created,
            launch_attempted_at_utc,
            deadline_utc,
            process_started_at_utc,
            pid,
            creation_identity,
            executable_path,
            executable_hash,
            supervisor_instance_id,
            completed_at_utc,
            native_exit_value,
            process_exit_category,
            cleanup_complete,
            cleanup_completed_at_utc,
            stderr_artifact_id,
            primary_diagnostic_id,
            diagnostic_ids,
            created_at_utc,
            updated_at_utc,
            revision,
        ),
    )


_EVENT_SQL: Final = (
    "INSERT INTO run_events (invocation_id, sequence, event_id, run_id,"
    " schema_version, protocol_version, attempt_token_hash, wire_event_hash,"
    " content_hash, event_type, timestamp_utc, received_at_utc, payload)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def event_row(
    invocation_id: str = INVOCATION_ID,
    sequence: int = 1,
    event_id: str = EVT_A,
    *,
    run_id: str = RUN_ID,
    protocol_version: str = "1.0.0",
    event_type: str = "HEARTBEAT",
) -> Statement:
    return (
        _EVENT_SQL,
        (
            invocation_id,
            sequence,
            event_id,
            run_id,
            "1.0.0",
            protocol_version,
            TOKEN_HASH,
            "b" * 64,
            "c" * 64,
            event_type,
            T0,
            T0,
            '{"activity_counter": 1}',
        ),
    )


_DECISION_SQL: Final = (
    "INSERT INTO retry_decisions (logical_slot_id, predecessor_run_id, schema_version,"
    " experiment_id, experiment_spec_hash, retry_policy, created_attempt_count,"
    " predecessor_terminal_state, primary_terminal_diagnostic_id, outcome,"
    " denial_reason, hard_block_error_code, availability_observation_id,"
    " retry_not_before_utc, reserved_successor_attempt_number, decided_at_utc)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def decision_row(
    logical_slot_id: str,
    predecessor_run_id: str,
    outcome: str,
    *,
    experiment_id: str = EXPERIMENT_ID,
    created_attempt_count: int = 1,
    predecessor_terminal_state: str = "FAILED",
    denial_reason: str | None = None,
    hard_block_error_code: str | None = None,
    availability_observation_id: str | None = None,
    retry_not_before_utc: int | None = None,
    reserved_successor_attempt_number: int | None = None,
    allowed_defaults: bool = True,
) -> Statement:
    if outcome == "ALLOWED" and allowed_defaults:
        retry_not_before_utc = (
            T0 + 30 * SECOND if retry_not_before_utc is None else retry_not_before_utc
        )
        if reserved_successor_attempt_number is None:
            reserved_successor_attempt_number = created_attempt_count + 1
    if outcome == "DENIED" and denial_reason is None and allowed_defaults:
        denial_reason = "ATTEMPT_BUDGET_EXHAUSTED"
    return (
        _DECISION_SQL,
        (
            logical_slot_id,
            predecessor_run_id,
            "1.0.0",
            experiment_id,
            SPEC_HASH,
            "{}",
            created_attempt_count,
            predecessor_terminal_state,
            DIAG_ID,
            outcome,
            denial_reason,
            hard_block_error_code,
            availability_observation_id,
            retry_not_before_utc,
            reserved_successor_attempt_number,
            T0,
        ),
    )


_OWNER_SQL: Final = (
    "INSERT INTO artifact_owners (owner_hash, owner_kind, experiment_id, run_id,"
    " invocation_id, dataset_id, strategy_version_id, strategy_version_hash,"
    " adapter_name, adapter_version, engine_name, engine_version, core_component,"
    " correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def owner_row(
    owner_hash: str,
    owner_kind: str,
    *,
    experiment_id: str | None = None,
    run_id: str | None = None,
    invocation_id: str | None = None,
    dataset_id: str | None = None,
    strategy_version_id: str | None = None,
    strategy_version_hash: str | None = None,
    adapter_name: str | None = None,
    adapter_version: str | None = None,
    engine_name: str | None = None,
    engine_version: str | None = None,
    core_component: str | None = None,
    correlation_id: str | None = None,
) -> Statement:
    return (
        _OWNER_SQL,
        (
            owner_hash,
            owner_kind,
            experiment_id,
            run_id,
            invocation_id,
            dataset_id,
            strategy_version_id,
            strategy_version_hash,
            adapter_name,
            adapter_version,
            engine_name,
            engine_version,
            core_component,
            correlation_id,
        ),
    )


def _cause_row(diagnostic_id: str, causal_diagnostic_id: str) -> Statement:
    return (
        "INSERT INTO diagnostic_causes (diagnostic_id, causal_diagnostic_id)"
        " VALUES (?, ?)",
        (diagnostic_id, causal_diagnostic_id),
    )


def _new_hash(index: int) -> str:
    return f"{index:064x}"


# --------------------------------------------------------------------------
# The seed (plan 7.1 ``seeded_database``): dependency order, every FK satisfied
# --------------------------------------------------------------------------

SEED_STATEMENTS: Final[tuple[Statement, ...]] = (
    experiment_row(
        EXPERIMENT_ID, "QUEUED", slot_compatibility="[]", revision=2, snapshot=True
    ),
    experiment_row(
        OTHER_EXPERIMENT_ID,
        "COMPLETED",
        slot_compatibility="[]",
        revision=5,
        snapshot=True,
    ),
    experiment_row(EXP_C, "VALIDATED", revision=1),
    experiment_row(EXP_D, "DRAFT"),
    slot_row(EXPERIMENT_ID, SLOT_A, 0),
    slot_row(
        EXPERIMENT_ID,
        SLOT_B,
        1,
        adapter=("adapter.beta", "1.2.0"),
        engine=("engine.beta", "2.3.4"),
    ),
    slot_row(OTHER_EXPERIMENT_ID, SLOT_A, 0),
    slot_row(EXP_C, SLOT_A, 0),
    observation_row(AVAIL_A),
    diagnostic_row(OTHER_DIAG_ID),
    diagnostic_row(
        DIAG_ID,
        error_code="ENGINE.RUNTIME_FAILURE",
        category="ENGINE_RUNTIME",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
        causal_diagnostic_ids=json.dumps([OTHER_DIAG_ID]),
    ),
    _cause_row(DIAG_ID, OTHER_DIAG_ID),
    strategy_version_row(),
    dataset_row(),
    partition_row(),
    run_row(
        RUN_ID,
        "FAILED",
        primary_terminal_diagnostic_id=DIAG_ID,
        availability_observation_id=AVAIL_A,
        revision=3,
    ),
    run_row(OTHER_RUN_ID, "PENDING", logical_slot_id=SLOT_B),
    invocation_row(
        INVOCATION_ID,
        "EXITED",
        native_exit_value=40,
        process_exit_category="RUNTIME_FAILURE",
        cleanup_complete=1,
        cleanup_completed_at_utc=T0,
        primary_diagnostic_id=DIAG_ID,
        diagnostic_ids=json.dumps([DIAG_ID]),
        revision=4,
    ),
    invocation_row(
        OTHER_INVOCATION_ID,
        "PENDING",
        command_kind="VALIDATE",
        run_id=OTHER_RUN_ID,
        timeout_seconds=30,
    ),
    invocation_row(INV_C, "PENDING", command_kind="DESCRIBE", run_id=None),
    event_row(),
    decision_row(SLOT_A, RUN_ID, "DENIED"),
    owner_row(
        OWNER_HASH,
        "RUN",
        experiment_id=EXPERIMENT_ID,
        run_id=RUN_ID,
        invocation_id=INVOCATION_ID,
    ),
)

# --------------------------------------------------------------------------
# The refusals (C-27): label, statement, expected classification
# --------------------------------------------------------------------------

_INV: Final = INVARIANT_VIOLATION
_CONF: Final = CONCURRENCY_CONFLICT
_TOO_MANY_DIAGNOSTIC_IDS: Final = json.dumps(
    [f"diag_{_uuid(index)}" for index in range(65)]
)
_TOO_MANY_CAUSES: Final = json.dumps([f"diag_{_uuid(index)}" for index in range(33)])
_OVERSIZED_DETAILS: Final = '{"k": "' + "x" * 16_400 + '"}'
_OVERSIZED_SNAPSHOT: Final = '"' + "x" * 1_048_576 + '"'

TERMINAL_STATE_CHANGE_STATEMENTS: Final[
    tuple[tuple[str, str, tuple[object, ...], str], ...]
] = (
    # -- triggers (plan 3.4) ------------------------------------------------
    (
        "T-EXP-TERMINAL: a terminal experiment accepts no update",
        "UPDATE experiments SET revision = revision + 1 WHERE experiment_id = ?",
        (OTHER_EXPERIMENT_ID,),
        _INV,
    ),
    (
        "T-EXP-TERMINAL: a terminal experiment refuses a state change",
        "UPDATE experiments SET state = 'RUNNING' WHERE experiment_id = ?",
        (OTHER_EXPERIMENT_ID,),
        _INV,
    ),
    (
        "T-EXP-FROZEN: the spec is frozen at QUEUED",
        "UPDATE experiments SET spec = '{\"changed\": 1}', spec_hash = ?"
        " WHERE experiment_id = ?",
        ("b" * 64, EXPERIMENT_ID),
        _INV,
    ),
    (
        "T-EXP-FROZEN: a hash projection is frozen at QUEUED",
        "UPDATE experiments SET strategy_version_hash = ? WHERE experiment_id = ?",
        ("b" * 64, EXPERIMENT_ID),
        _INV,
    ),
    (
        "T-EXP-SNAPSHOT-FROZEN: the snapshot is frozen at QUEUED",
        "UPDATE experiments SET configuration_snapshot_json = '{\"other\": 1}'"
        " WHERE experiment_id = ?",
        (EXPERIMENT_ID,),
        _INV,
    ),
    (
        "T-EXP-SNAPSHOT-FROZEN: a frozen snapshot is never cleared",
        "UPDATE experiments SET configuration_snapshot_schema_version = NULL,"
        " configuration_snapshot_json = NULL, configuration_audit_hash = NULL,"
        " material_base_configuration_hash = NULL WHERE experiment_id = ?",
        (EXPERIMENT_ID,),
        _INV,
    ),
    (
        "T-EXP-QUEUE-SNAPSHOT: no queue edge without a frozen snapshot",
        "UPDATE experiments SET state = 'QUEUED', slot_compatibility = '[]',"
        " revision = 2 WHERE experiment_id = ?",
        (EXP_C,),
        _INV,
    ),
    (
        "T-RUN-TERMINAL: a terminal run accepts no update",
        "UPDATE engine_runs SET revision = revision + 1 WHERE run_id = ?",
        (RUN_ID,),
        _INV,
    ),
    (
        "T-INV-TERMINAL: a terminal invocation state is immutable",
        "UPDATE command_invocations SET state = 'CANCELLED' WHERE invocation_id = ?",
        (INVOCATION_ID,),
        _INV,
    ),
    *(
        (
            f"T-APPEND-ONLY: {table} refuses an update",
            f"UPDATE {table} SET {column} = {column} WHERE {key} = ?",  # noqa: S608
            (value,),
            _INV,
        )
        for table, column, key, value in (
            ("run_events", "sequence", "event_id", EVT_A),
            ("retry_decisions", "outcome", "predecessor_run_id", RUN_ID),
            (
                "runtime_availability_observations",
                "available",
                "availability_observation_id",
                AVAIL_A,
            ),
            ("diagnostics", "message", "diagnostic_id", DIAG_ID),
            ("diagnostic_causes", "diagnostic_id", "diagnostic_id", DIAG_ID),
            ("strategy_versions", "record", "content_hash", STRATEGY_HASH),
            ("datasets", "record", "dataset_id", DS_A),
            ("dataset_partitions", "record", "partition_id", PART_A),
            ("artifact_owners", "owner_kind", "owner_hash", OWNER_HASH),
        )
    ),
    *(
        (
            f"T-APPEND-ONLY: {table} refuses a delete",
            f"DELETE FROM {table} WHERE {key} = ?",  # noqa: S608
            (value,),
            _INV,
        )
        for table, key, value in (
            ("run_events", "event_id", EVT_A),
            ("retry_decisions", "predecessor_run_id", RUN_ID),
            (
                "runtime_availability_observations",
                "availability_observation_id",
                AVAIL_A,
            ),
            ("diagnostics", "diagnostic_id", OTHER_DIAG_ID),
            ("diagnostic_causes", "diagnostic_id", DIAG_ID),
            ("strategy_versions", "content_hash", STRATEGY_HASH),
            ("datasets", "dataset_id", DS_A),
            ("dataset_partitions", "partition_id", PART_A),
            ("artifact_owners", "owner_hash", OWNER_HASH),
        )
    ),
    (
        "T-NO-DELETE: experiments rows are never deleted",
        "DELETE FROM experiments WHERE experiment_id = ?",
        (EXP_D,),
        _INV,
    ),
    (
        "T-NO-DELETE: engine_runs rows are never deleted",
        "DELETE FROM engine_runs WHERE run_id = ?",
        (OTHER_RUN_ID,),
        _INV,
    ),
    (
        "T-NO-DELETE: command_invocations rows are never deleted",
        "DELETE FROM command_invocations WHERE invocation_id = ?",
        (INV_C,),
        _INV,
    ),
    # -- experiments CHECKs (plan 3.3.1) -------------------------------------
    (
        "diagnostic_causes: a self-cause edge",
        *_cause_row(OTHER_DIAG_ID, OTHER_DIAG_ID),
        _INV,
    ),
    (
        "experiments: a partially filled snapshot",
        *experiment_row(EXP_E, "DRAFT", snapshot_json="{}"),
        _INV,
    ),
    (
        "experiments: a snapshot missing one hash",
        *experiment_row(
            EXP_E,
            "DRAFT",
            snapshot_schema_version="1.0.0",
            snapshot_json="{}",
            audit_hash=AUDIT_HASH,
        ),
        _INV,
    ),
    (
        "experiments: updated before created",
        *experiment_row(EXP_E, "DRAFT", updated_at_utc=T0 - 1),
        _INV,
    ),
    (
        "experiments: CANCELLED without a correlation id",
        *experiment_row(EXP_E, "CANCELLED"),
        _INV,
    ),
    (
        "experiments: a correlation id outside CANCELLED",
        *experiment_row(EXP_E, "DRAFT", cancellation_correlation_id="corr-1"),
        _INV,
    ),
    (
        "experiments: DRAFT with slot compatibility",
        *experiment_row(EXP_E, "DRAFT", slot_compatibility="[]"),
        _INV,
    ),
    (
        "experiments: QUEUED without slot compatibility",
        *experiment_row(EXP_E, "QUEUED", revision=2, snapshot=True),
        _INV,
    ),
    ("experiments: an unknown state", *experiment_row(EXP_E, "BOGUS"), _INV),
    (
        "experiments: a non-hex spec hash",
        *experiment_row(EXP_E, "DRAFT", spec_hash="g" * 64),
        _INV,
    ),
    (
        "experiments: a wrong identifier prefix",
        *experiment_row(f"run_{UUID_E}", "DRAFT"),
        _INV,
    ),
    (
        "experiments: a negative revision",
        *experiment_row(EXP_E, "DRAFT", revision=-1),
        _INV,
    ),
    (
        "experiments: a foreign schema version",
        *experiment_row(EXP_E, "DRAFT", schema_version="2.0.0"),
        _INV,
    ),
    (
        "experiments: an oversized configuration snapshot",
        *experiment_row(
            EXP_E, "DRAFT", snapshot=True, snapshot_json=_OVERSIZED_SNAPSHOT
        ),
        _INV,
    ),
    (
        "experiments: a snapshot envelope other than 1.0.0",
        *experiment_row(EXP_E, "DRAFT", snapshot=True, snapshot_schema_version="1.1.0"),
        _INV,
    ),
    # -- engine_slots (plan 3.3.2) -------------------------------------------
    ("engine_slots: an ordinal above seven", *slot_row(EXP_D, SLOT_A, 8), _INV),
    (
        "engine_slots: a duplicate ordinal within the experiment",
        *slot_row(EXPERIMENT_ID, f"slot_{UUID_E}", 0),
        _CONF,
    ),
    (
        "engine_slots: a duplicate slot within the experiment",
        *slot_row(EXPERIMENT_ID, SLOT_A, 5),
        _CONF,
    ),
    ("engine_slots: an unknown experiment", *slot_row(EXP_E, SLOT_A, 0), _INV),
    # -- engine_runs (plan 3.3.3) ---------------------------------------------
    (
        "engine_runs: a second attempt without a predecessor",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            attempt_number=2,
            retry_reason="FAILED",
        ),
        _INV,
    ),
    (
        "engine_runs: a first attempt with a predecessor",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            predecessor_run_id=RUN_ID,
        ),
        _INV,
    ),
    (
        "engine_runs: a second attempt without a retry reason",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            attempt_number=2,
            predecessor_run_id=RUN_ID,
        ),
        _INV,
    ),
    (
        "engine_runs: a run that is its own predecessor",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            attempt_number=2,
            predecessor_run_id=THIRD_RUN_ID,
            retry_reason="FAILED",
        ),
        _INV,
    ),
    (
        "engine_runs: a non-success terminal without a primary diagnostic",
        *run_row(THIRD_RUN_ID, "FAILED", experiment_id=OTHER_EXPERIMENT_ID),
        _INV,
    ),
    (
        "engine_runs: a pending run with a primary diagnostic",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            primary_terminal_diagnostic_id=DIAG_ID,
        ),
        _INV,
    ),
    (
        "engine_runs: a pending run with an observation",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            availability_observation_id=AVAIL_A,
        ),
        _INV,
    ),
    (
        "engine_runs: a ready run without an observation",
        *run_row(THIRD_RUN_ID, "READY", experiment_id=OTHER_EXPERIMENT_ID),
        _INV,
    ),
    (
        "engine_runs: an unregistered observation",
        *run_row(
            THIRD_RUN_ID,
            "READY",
            experiment_id=OTHER_EXPERIMENT_ID,
            availability_observation_id=AVAIL_B,
        ),
        _INV,
    ),
    (
        "engine_runs: an attempt number above five",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            attempt_number=6,
            predecessor_run_id=RUN_ID,
            retry_reason="FAILED",
        ),
        _INV,
    ),
    (
        "engine_runs: an unknown state",
        *run_row(THIRD_RUN_ID, "BOGUS", experiment_id=OTHER_EXPERIMENT_ID),
        _INV,
    ),
    (
        "engine_runs: updated before created",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            experiment_id=OTHER_EXPERIMENT_ID,
            updated_at_utc=T0 - 1,
        ),
        _INV,
    ),
    (
        "engine_runs: the attempt triple is unique",
        *run_row(THIRD_RUN_ID, "PENDING"),
        _CONF,
    ),
    (
        "engine_runs: a slot of another experiment (composite key)",
        *run_row(THIRD_RUN_ID, "PENDING", experiment_id=EXP_C, logical_slot_id=SLOT_B),
        _INV,
    ),
    (
        "engine_runs: one active attempt per slot (partial index)",
        *run_row(
            THIRD_RUN_ID,
            "PENDING",
            logical_slot_id=SLOT_B,
            attempt_number=2,
            predecessor_run_id=OTHER_RUN_ID,
            retry_reason="FAILED",
        ),
        _CONF,
    ),
    # -- command_invocations, the 15.2 rows (plan 3.3.4) ---------------------
    (
        "command_invocations: DESCRIBE with a run",
        *invocation_row(f"inv_{UUID_D}", "PENDING", command_kind="DESCRIBE"),
        _INV,
    ),
    (
        "command_invocations: VALIDATE without a run",
        *invocation_row(
            f"inv_{UUID_D}", "PENDING", command_kind="VALIDATE", run_id=None
        ),
        _INV,
    ),
    (
        "command_invocations: a DESCRIBE timeout above 300",
        *invocation_row(
            f"inv_{UUID_D}",
            "PENDING",
            command_kind="DESCRIBE",
            run_id=None,
            timeout_seconds=301,
        ),
        _INV,
    ),
    (
        "command_invocations: a VALIDATE timeout above 1800",
        *invocation_row(
            f"inv_{UUID_D}", "PENDING", command_kind="VALIDATE", timeout_seconds=1801
        ),
        _INV,
    ),
    (
        "command_invocations: a RUN timeout above 604800",
        *invocation_row(f"inv_{UUID_D}", "PENDING", timeout_seconds=604_801),
        _INV,
    ),
    (
        "command_invocations: a timeout below one",
        *invocation_row(f"inv_{UUID_D}", "PENDING", timeout_seconds=0),
        _INV,
    ),
    (
        "command_invocations: a launch instant without a deadline",
        *invocation_row(
            f"inv_{UUID_D}", "STARTING", launched=False, launch_attempted_at_utc=T0
        ),
        _INV,
    ),
    (
        "command_invocations: a deadline other than launch plus timeout",
        *invocation_row(f"inv_{UUID_D}", "STARTING", deadline_utc=T0 + 61 * SECOND),
        _INV,
    ),
    (
        "command_invocations: a created process without a pid",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", process=False, process_created=1),
        _INV,
    ),
    (
        "command_invocations: process columns with mixed presence",
        *invocation_row(f"inv_{UUID_D}", "STARTING", pid=4242),
        _INV,
    ),
    (
        "command_invocations: a native exit without a category",
        *invocation_row(
            f"inv_{UUID_D}", "EXITED", native_exit_value=0, process_exit_category=None
        ),
        _INV,
    ),
    (
        "command_invocations: a category disagreeing with the exit value",
        *invocation_row(
            f"inv_{UUID_D}",
            "EXITED",
            native_exit_value=0,
            process_exit_category="RUNTIME_FAILURE",
        ),
        _INV,
    ),
    (
        "command_invocations: an unrecognized exit mapped to SUCCESS",
        *invocation_row(
            f"inv_{UUID_D}",
            "EXITED",
            native_exit_value=99,
            process_exit_category="SUCCESS",
            primary_diagnostic_id=DIAG_ID,
            diagnostic_ids=json.dumps([DIAG_ID]),
        ),
        _INV,
    ),
    (
        "command_invocations: cleanup complete without an instant",
        *invocation_row(f"inv_{UUID_D}", "EXITED", cleanup_complete=1),
        _INV,
    ),
    (
        "command_invocations: a cleanup instant without cleanup",
        *invocation_row(f"inv_{UUID_D}", "EXITED", cleanup_completed_at_utc=T0),
        _INV,
    ),
    (
        "command_invocations: a non-terminal row with a completion instant",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", completed=True),
        _INV,
    ),
    (
        "command_invocations: a terminal row without a completion instant",
        *invocation_row(f"inv_{UUID_D}", "EXITED", completed=False),
        _INV,
    ),
    (
        "command_invocations: a non-terminal row with cleanup complete",
        *invocation_row(
            f"inv_{UUID_D}", "RUNNING", cleanup_complete=1, cleanup_completed_at_utc=T0
        ),
        _INV,
    ),
    (
        "command_invocations: a non-terminal row with a primary diagnostic",
        *invocation_row(
            f"inv_{UUID_D}",
            "RUNNING",
            primary_diagnostic_id=DIAG_ID,
            diagnostic_ids=json.dumps([DIAG_ID]),
        ),
        _INV,
    ),
    (
        "command_invocations: a non-terminal row with a stderr artifact",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", stderr_artifact_id=f"art_{UUID_A}"),
        _INV,
    ),
    (
        "command_invocations: PENDING with a deadline",
        *invocation_row(f"inv_{UUID_D}", "PENDING", launched=True),
        _INV,
    ),
    (
        "command_invocations: PENDING with a created process",
        *invocation_row(f"inv_{UUID_D}", "PENDING", process=True),
        _INV,
    ),
    (
        "command_invocations: STARTING without a deadline",
        *invocation_row(f"inv_{UUID_D}", "STARTING", launched=False),
        _INV,
    ),
    (
        "command_invocations: STARTING with a created process",
        *invocation_row(f"inv_{UUID_D}", "STARTING", process=True),
        _INV,
    ),
    (
        "command_invocations: RUNNING without a created process",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", process=False),
        _INV,
    ),
    (
        "command_invocations: RUNNING without a deadline",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", launched=False),
        _INV,
    ),
    (
        "command_invocations: EXITED without a native exit",
        *invocation_row(f"inv_{UUID_D}", "EXITED", terminal_defaults=False),
        _INV,
    ),
    (
        "command_invocations: EXITED without a created process",
        *invocation_row(f"inv_{UUID_D}", "EXITED", process=False),
        _INV,
    ),
    (
        "command_invocations: EXITED with an unrecognized exit and no diagnostic",
        *invocation_row(
            f"inv_{UUID_D}",
            "EXITED",
            native_exit_value=99,
            process_exit_category="RUNTIME_FAILURE",
        ),
        _INV,
    ),
    (
        "command_invocations: FAILED_TO_START with a native exit",
        *invocation_row(
            f"inv_{UUID_D}",
            "FAILED_TO_START",
            command_kind="DESCRIBE",
            run_id=None,
            native_exit_value=1,
            process_exit_category="RUNTIME_FAILURE",
        ),
        _INV,
    ),
    (
        "command_invocations: FAILED_TO_START without a primary diagnostic",
        *invocation_row(
            f"inv_{UUID_D}",
            "FAILED_TO_START",
            command_kind="DESCRIBE",
            run_id=None,
            terminal_defaults=False,
        ),
        _INV,
    ),
    (
        "command_invocations: FAILED_TO_START with a created process",
        *invocation_row(
            f"inv_{UUID_D}",
            "FAILED_TO_START",
            command_kind="DESCRIBE",
            run_id=None,
            process=True,
        ),
        _INV,
    ),
    (
        "command_invocations: CANCELLED without a primary diagnostic",
        *invocation_row(f"inv_{UUID_D}", "CANCELLED", terminal_defaults=False),
        _INV,
    ),
    (
        "command_invocations: CANCELLED with process facts but no deadline",
        *invocation_row(f"inv_{UUID_D}", "CANCELLED", launched=False, process=True),
        _INV,
    ),
    (
        "command_invocations: TIMED_OUT without a deadline",
        *invocation_row(f"inv_{UUID_D}", "TIMED_OUT", launched=False),
        _INV,
    ),
    (
        "command_invocations: TIMED_OUT without a primary diagnostic",
        *invocation_row(f"inv_{UUID_D}", "TIMED_OUT", terminal_defaults=False),
        _INV,
    ),
    (
        "command_invocations: PROTOCOL_FAILED without a created process",
        *invocation_row(f"inv_{UUID_D}", "PROTOCOL_FAILED", process=False),
        _INV,
    ),
    (
        "command_invocations: PROTOCOL_FAILED without a primary diagnostic",
        *invocation_row(f"inv_{UUID_D}", "PROTOCOL_FAILED", terminal_defaults=False),
        _INV,
    ),
    (
        "command_invocations: more than 64 diagnostic ids",
        *invocation_row(
            f"inv_{UUID_D}", "PENDING", diagnostic_ids=_TOO_MANY_DIAGNOSTIC_IDS
        ),
        _INV,
    ),
    (
        "command_invocations: a pid of zero",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", pid=0),
        _INV,
    ),
    (
        "command_invocations: a pid above the 32-bit range",
        *invocation_row(f"inv_{UUID_D}", "RUNNING", pid=4_294_967_296),
        _INV,
    ),
    (
        "command_invocations: a native exit below the range",
        *invocation_row(
            f"inv_{UUID_D}",
            "EXITED",
            native_exit_value=-2_147_483_649,
            process_exit_category="RUNTIME_FAILURE",
            primary_diagnostic_id=DIAG_ID,
            diagnostic_ids=json.dumps([DIAG_ID]),
        ),
        _INV,
    ),
    (
        "command_invocations: an unknown state",
        *invocation_row(f"inv_{UUID_D}", "BOGUS"),
        _INV,
    ),
    (
        "command_invocations: an unknown command kind",
        *invocation_row(f"inv_{UUID_D}", "PENDING", command_kind="BOGUS"),
        _INV,
    ),
    (
        "command_invocations: one open invocation per run and kind (partial index)",
        *invocation_row(
            f"inv_{UUID_D}", "STARTING", command_kind="VALIDATE", run_id=OTHER_RUN_ID
        ),
        _CONF,
    ),
    (
        "command_invocations: an unknown run",
        *invocation_row(f"inv_{UUID_D}", "PENDING", run_id=THIRD_RUN_ID),
        _INV,
    ),
    # -- run_events (plan 3.3.5) ----------------------------------------------
    (
        "run_events: an event for an invocation of another run",
        *event_row(OTHER_INVOCATION_ID, 1, f"evt_{UUID_D}", run_id=RUN_ID),
        _INV,
    ),
    (
        "run_events: a DESCRIBE invocation never owns an event",
        *event_row(INV_C, 1, f"evt_{UUID_D}", run_id=RUN_ID),
        _INV,
    ),
    (
        "run_events: a sequence of zero",
        *event_row(INVOCATION_ID, 0, f"evt_{UUID_D}"),
        _INV,
    ),
    (
        "run_events: a sequence above one million",
        *event_row(INVOCATION_ID, 1_000_001, f"evt_{UUID_D}"),
        _INV,
    ),
    ("run_events: a reused event id", *event_row(INVOCATION_ID, 2, EVT_A), _CONF),
    (
        "run_events: a reused invocation-sequence key",
        *event_row(INVOCATION_ID, 1, f"evt_{UUID_D}"),
        _CONF,
    ),
    (
        "run_events: an unknown event type",
        *event_row(INVOCATION_ID, 2, f"evt_{UUID_D}", event_type="BOGUS"),
        _INV,
    ),
    (
        "run_events: a foreign protocol version",
        *event_row(INVOCATION_ID, 2, f"evt_{UUID_D}", protocol_version="2.0.0"),
        _INV,
    ),
    # -- retry_decisions (plan 3.3.6) ----------------------------------------
    (
        "retry_decisions: DENIED without a denial reason",
        *decision_row(SLOT_B, OTHER_RUN_ID, "DENIED", allowed_defaults=False),
        _INV,
    ),
    (
        "retry_decisions: ALLOWED with a denial reason",
        *decision_row(
            SLOT_B, OTHER_RUN_ID, "ALLOWED", denial_reason="ATTEMPT_BUDGET_EXHAUSTED"
        ),
        _INV,
    ),
    (
        "retry_decisions: HARD_BLOCKED without an error code",
        *decision_row(
            SLOT_B, OTHER_RUN_ID, "DENIED", denial_reason="HARD_BLOCKED_OUTCOME"
        ),
        _INV,
    ),
    (
        "retry_decisions: an error code with another denial reason",
        *decision_row(
            SLOT_B,
            OTHER_RUN_ID,
            "DENIED",
            denial_reason="EXPERIMENT_TERMINAL",
            hard_block_error_code="ENGINE.RUNTIME_FAILURE",
        ),
        _INV,
    ),
    (
        "retry_decisions: ALLOWED without a not-before instant",
        *decision_row(
            SLOT_B,
            OTHER_RUN_ID,
            "ALLOWED",
            allowed_defaults=False,
            reserved_successor_attempt_number=2,
        ),
        _INV,
    ),
    (
        "retry_decisions: ALLOWED without a reserved attempt number",
        *decision_row(
            SLOT_B,
            OTHER_RUN_ID,
            "ALLOWED",
            allowed_defaults=False,
            retry_not_before_utc=T0 + 30 * SECOND,
        ),
        _INV,
    ),
    (
        "retry_decisions: a reserved number other than count plus one",
        *decision_row(
            SLOT_B, OTHER_RUN_ID, "ALLOWED", reserved_successor_attempt_number=3
        ),
        _INV,
    ),
    (
        "retry_decisions: ALLOWED after UNAVAILABLE without an observation",
        *decision_row(
            SLOT_B, OTHER_RUN_ID, "ALLOWED", predecessor_terminal_state="UNAVAILABLE"
        ),
        _INV,
    ),
    (
        "retry_decisions: ALLOWED after FAILED with an observation",
        *decision_row(
            SLOT_B, OTHER_RUN_ID, "ALLOWED", availability_observation_id=AVAIL_A
        ),
        _INV,
    ),
    (
        "retry_decisions: a success terminal as the predecessor state",
        *decision_row(
            SLOT_B, OTHER_RUN_ID, "DENIED", predecessor_terminal_state="SUCCEEDED"
        ),
        _INV,
    ),
    (
        "retry_decisions: a created attempt count of zero",
        *decision_row(SLOT_B, OTHER_RUN_ID, "DENIED", created_attempt_count=0),
        _INV,
    ),
    (
        "retry_decisions: a created attempt count above five",
        *decision_row(SLOT_B, OTHER_RUN_ID, "DENIED", created_attempt_count=6),
        _INV,
    ),
    (
        "retry_decisions: a predecessor of another experiment (composite key)",
        *decision_row(SLOT_A, OTHER_RUN_ID, "DENIED", experiment_id=EXP_C),
        _INV,
    ),
    (
        "retry_decisions: a duplicate decision key",
        *decision_row(SLOT_A, RUN_ID, "DENIED"),
        _CONF,
    ),
    # -- artifact_owners (plan 3.3.12) ----------------------------------------
    (
        "artifact_owners: RUN without a run",
        *owner_row(_new_hash(2), "RUN", experiment_id=EXPERIMENT_ID),
        _INV,
    ),
    (
        "artifact_owners: RUN with a dataset",
        *owner_row(
            _new_hash(2),
            "RUN",
            experiment_id=EXPERIMENT_ID,
            run_id=RUN_ID,
            dataset_id=DS_A,
        ),
        _INV,
    ),
    (
        "artifact_owners: EXPERIMENT with a run",
        *owner_row(
            _new_hash(2), "EXPERIMENT", experiment_id=EXPERIMENT_ID, run_id=RUN_ID
        ),
        _INV,
    ),
    (
        "artifact_owners: DATASET without a dataset",
        *owner_row(_new_hash(2), "DATASET"),
        _INV,
    ),
    (
        "artifact_owners: STRATEGY with both identities",
        *owner_row(
            _new_hash(2),
            "STRATEGY",
            strategy_version_id=STRV_A,
            strategy_version_hash=STRATEGY_HASH,
        ),
        _INV,
    ),
    (
        "artifact_owners: STRATEGY with no identity",
        *owner_row(_new_hash(2), "STRATEGY"),
        _INV,
    ),
    (
        "artifact_owners: ADAPTER with an engine name alone",
        *owner_row(
            _new_hash(2),
            "ADAPTER",
            adapter_name="adapter.alpha",
            adapter_version="1.0.0",
            engine_name="engine.alpha",
        ),
        _INV,
    ),
    (
        "artifact_owners: ADAPTER without a version",
        *owner_row(_new_hash(2), "ADAPTER", adapter_name="adapter.alpha"),
        _INV,
    ),
    (
        "artifact_owners: SYSTEM without a correlation id",
        *owner_row(_new_hash(2), "SYSTEM", core_component="core.scheduler"),
        _INV,
    ),
    ("artifact_owners: an unknown kind", *owner_row(_new_hash(2), "BOGUS"), _INV),
    (
        "artifact_owners: RUN naming an unpersisted run",
        *owner_row(
            _new_hash(2), "RUN", experiment_id=EXPERIMENT_ID, run_id=THIRD_RUN_ID
        ),
        _INV,
    ),
    (
        "artifact_owners: RUN whose run belongs to another experiment",
        *owner_row(
            _new_hash(2), "RUN", experiment_id=OTHER_EXPERIMENT_ID, run_id=RUN_ID
        ),
        _INV,
    ),
    (
        "artifact_owners: RUN whose invocation belongs to another run",
        *owner_row(
            _new_hash(2),
            "RUN",
            experiment_id=EXPERIMENT_ID,
            run_id=RUN_ID,
            invocation_id=OTHER_INVOCATION_ID,
        ),
        _INV,
    ),
    (
        "artifact_owners: STRATEGY naming an unknown hash",
        *owner_row(_new_hash(2), "STRATEGY", strategy_version_hash="9" * 64),
        _INV,
    ),
    (
        "artifact_owners: DATASET naming an unknown dataset",
        *owner_row(_new_hash(2), "DATASET", dataset_id=f"ds_{UUID_E}"),
        _INV,
    ),
    (
        "artifact_owners: a duplicate owner hash",
        *owner_row(OWNER_HASH, "EXPERIMENT", experiment_id=EXPERIMENT_ID),
        _CONF,
    ),
    # -- runtime_availability_observations (plan 3.3.7) -----------------------
    (
        "observations: available with a reason code",
        *observation_row(AVAIL_B, reason_code="ADAPTER.UNAVAILABLE"),
        _INV,
    ),
    (
        "observations: unavailable without a reason code",
        *observation_row(AVAIL_B, available=0),
        _INV,
    ),
    (
        "observations: expiry not after the observation",
        *observation_row(AVAIL_B, expires_at_utc=T0),
        _INV,
    ),
    (
        "observations: an unknown operating system",
        *observation_row(AVAIL_B, operating_system="BOGUS"),
        _INV,
    ),
    # -- diagnostics (plan 3.3.8, 3.3.9) --------------------------------------
    (
        "diagnostics: a run correlation without an experiment",
        *diagnostic_row(f"diag_{UUID_D}", run_id=RUN_ID),
        _INV,
    ),
    (
        "diagnostics: a command category without an invocation",
        *diagnostic_row(
            f"diag_{UUID_D}", error_code="PROCESS.RUN_TIMED_OUT", category="TIMEOUT"
        ),
        _INV,
    ),
    (
        "diagnostics: more than 32 causes",
        *diagnostic_row(f"diag_{UUID_D}", causal_diagnostic_ids=_TOO_MANY_CAUSES),
        _INV,
    ),
    (
        "diagnostics: oversized details",
        *diagnostic_row(f"diag_{UUID_D}", details=_OVERSIZED_DETAILS),
        _INV,
    ),
    (
        "diagnostics: an unknown severity",
        *diagnostic_row(f"diag_{UUID_D}", severity="BOGUS"),
        _INV,
    ),
    (
        "diagnostics: an error code shorter than three characters",
        *diagnostic_row(f"diag_{UUID_D}", error_code="AB"),
        _INV,
    ),
    (
        "diagnostics: an empty message",
        *diagnostic_row(f"diag_{UUID_D}", message=""),
        _INV,
    ),
    (
        "diagnostic_causes: an edge to an unrecorded cause",
        *_cause_row(OTHER_DIAG_ID, f"diag_{UUID_D}"),
        _INV,
    ),
    # -- registries (plan 3.3.10, 3.3.11) ------------------------------------
    (
        "strategy_versions: a foreign hashing profile version",
        *strategy_version_row(
            "8" * 64, f"strv_{UUID_D}", hashing_profile_version="strategy-version/v2"
        ),
        _INV,
    ),
    (
        "strategy_versions: two versions of one strategy at one instant",
        *strategy_version_row("8" * 64, f"strv_{UUID_D}"),
        _CONF,
    ),
    (
        "strategy_versions: a reused version id",
        *strategy_version_row("8" * 64, STRV_A, created_at_utc=T0 + 1),
        _CONF,
    ),
    (
        "datasets: an interval that does not start before it ends",
        *dataset_row(f"ds_{UUID_D}", "8" * 64, start_utc=T0),
        _INV,
    ),
    (
        "datasets: an unknown data type",
        *dataset_row(f"ds_{UUID_D}", "8" * 64, data_type="BOGUS"),
        _INV,
    ),
    ("datasets: a reused content hash", *dataset_row(f"ds_{UUID_D}"), _CONF),
    (
        "datasets: OHLCV without a timeframe",
        *dataset_row(f"ds_{UUID_D}", "8" * 64, timeframe=None),
        _INV,
    ),
    (
        "datasets: a timeframe on a non-OHLCV dataset",
        *dataset_row(f"ds_{UUID_D}", "8" * 64, data_type="TRADES"),
        _INV,
    ),
    (
        "dataset_partitions: an interval that does not start before it ends",
        *partition_row(
            f"part_{UUID_D}", ordinal=1, content_hash="8" * 64, start_utc=T0, end_utc=T0
        ),
        _INV,
    ),
    (
        "dataset_partitions: a negative ordinal",
        *partition_row(f"part_{UUID_D}", ordinal=-1, content_hash="8" * 64),
        _INV,
    ),
    (
        "dataset_partitions: a reused ordinal within the dataset",
        *partition_row(f"part_{UUID_D}", content_hash="8" * 64),
        _CONF,
    ),
    (
        "dataset_partitions: an unknown dataset",
        *partition_row(
            f"part_{UUID_D}",
            dataset_id=f"ds_{UUID_D}",
            ordinal=1,
            content_hash="8" * 64,
        ),
        _INV,
    ),
)

# --------------------------------------------------------------------------
# Positive controls: the permitted writes pass
# --------------------------------------------------------------------------

PERMITTED_STATEMENTS: Final[tuple[tuple[str, str, tuple[object, ...]], ...]] = (
    (
        "same-state enrichment of a terminal invocation passes T-INV-TERMINAL",
        "UPDATE command_invocations SET stderr_artifact_id = ?, revision = revision + 1"
        " WHERE invocation_id = ?",
        (f"art_{UUID_A}", INVOCATION_ID),
    ),
    (
        "a same-state SET of state on a terminal invocation passes",
        "UPDATE command_invocations SET state = 'EXITED', revision = revision + 1"
        " WHERE invocation_id = ?",
        (INVOCATION_ID,),
    ),
    (
        "a DRAFT spec may change",
        "UPDATE experiments SET spec = '{\"v\": 2}', spec_hash = ?, revision = 1"
        " WHERE experiment_id = ?",
        ("b" * 64, EXP_D),
    ),
    (
        "a VALIDATED experiment may receive a snapshot",
        "UPDATE experiments SET configuration_snapshot_schema_version = '1.0.0',"
        " configuration_snapshot_json = '{}', configuration_audit_hash = ?,"
        " material_base_configuration_hash = ? WHERE experiment_id = ?",
        (AUDIT_HASH, MATERIAL_HASH, EXP_C),
    ),
    (
        "a non-terminal run may advance",
        "UPDATE engine_runs SET state = 'VALIDATING', revision = 1 WHERE run_id = ?",
        (OTHER_RUN_ID,),
    ),
    (
        "the slot projection of a pre-QUEUED experiment may be rewritten",
        "DELETE FROM engine_slots WHERE experiment_id = ? AND logical_slot_id = ?",
        (EXP_C, SLOT_A),
    ),
    (
        "a CANCELLED experiment carries its correlation id",
        *experiment_row(
            EXP_E, "CANCELLED", cancellation_correlation_id="corr-1", revision=3
        ),
    ),
    (
        "an unavailable observation carries a reason code",
        *observation_row(AVAIL_B, available=0, reason_code="ADAPTER.UNAVAILABLE"),
    ),
    (
        "a non-OHLCV dataset carries no timeframe",
        *dataset_row(f"ds_{UUID_D}", "8" * 64, data_type="TRADES", timeframe=None),
    ),
    *(
        (f"a shape-valid {state} run", *statement)
        for state, statement in (
            (
                "PENDING",
                run_row(THIRD_RUN_ID, "PENDING", experiment_id=OTHER_EXPERIMENT_ID),
            ),
            (
                "VALIDATING",
                run_row(THIRD_RUN_ID, "VALIDATING", experiment_id=OTHER_EXPERIMENT_ID),
            ),
            *(
                (
                    state,
                    run_row(
                        THIRD_RUN_ID,
                        state,
                        experiment_id=OTHER_EXPERIMENT_ID,
                        availability_observation_id=AVAIL_A,
                    ),
                )
                for state in (
                    "READY",
                    "STARTING",
                    "RUNNING",
                    "SUCCEEDED",
                    "SUCCEEDED_WITH_WARNINGS",
                )
            ),
            *(
                (
                    state,
                    run_row(
                        THIRD_RUN_ID,
                        state,
                        experiment_id=OTHER_EXPERIMENT_ID,
                        primary_terminal_diagnostic_id=DIAG_ID,
                    ),
                )
                for state in ("FAILED", "CANCELLED", "TIMED_OUT", "NOT_APPLICABLE")
            ),
            (
                "UNAVAILABLE",
                run_row(
                    THIRD_RUN_ID,
                    "UNAVAILABLE",
                    experiment_id=OTHER_EXPERIMENT_ID,
                    primary_terminal_diagnostic_id=DIAG_ID,
                    availability_observation_id=AVAIL_A,
                ),
            ),
            (
                "second-attempt PENDING",
                run_row(
                    THIRD_RUN_ID,
                    "PENDING",
                    experiment_id=OTHER_EXPERIMENT_ID,
                    attempt_number=2,
                    predecessor_run_id=RUN_ID,
                    retry_reason="FAILED",
                ),
            ),
        )
    ),
    *(
        (f"a shape-valid {state} invocation", *statement)
        for state, statement in (
            (
                "PENDING",
                invocation_row(f"inv_{UUID_D}", "PENDING", command_kind="VALIDATE"),
            ),
            ("STARTING", invocation_row(f"inv_{UUID_D}", "STARTING")),
            (
                "RUNNING",
                invocation_row(f"inv_{UUID_D}", "RUNNING", run_id=OTHER_RUN_ID),
            ),
            (
                "EXITED",
                invocation_row(
                    f"inv_{UUID_D}",
                    "EXITED",
                    command_kind="VALIDATE",
                    run_id=OTHER_RUN_ID,
                    cleanup_complete=1,
                    cleanup_completed_at_utc=T0,
                ),
            ),
            (
                "EXITED with an unrecognized exit and a diagnostic",
                invocation_row(
                    f"inv_{UUID_D}",
                    "EXITED",
                    native_exit_value=99,
                    process_exit_category="RUNTIME_FAILURE",
                    primary_diagnostic_id=DIAG_ID,
                    diagnostic_ids=json.dumps([DIAG_ID]),
                    stderr_artifact_id=f"art_{UUID_A}",
                ),
            ),
            (
                "FAILED_TO_START",
                invocation_row(
                    f"inv_{UUID_D}",
                    "FAILED_TO_START",
                    command_kind="DESCRIBE",
                    run_id=None,
                ),
            ),
            (
                "CANCELLED without launch facts",
                invocation_row(f"inv_{UUID_D}", "CANCELLED", launched=False),
            ),
            (
                "CANCELLED with process facts",
                invocation_row(f"inv_{UUID_D}", "CANCELLED", process=True),
            ),
            (
                "TIMED_OUT",
                invocation_row(
                    f"inv_{UUID_D}", "TIMED_OUT", command_kind="DESCRIBE", run_id=None
                ),
            ),
            (
                "PROTOCOL_FAILED",
                invocation_row(
                    f"inv_{UUID_D}", "PROTOCOL_FAILED", command_kind="VALIDATE"
                ),
            ),
        )
    ),
    *(
        (f"a shape-valid {label} decision", *statement)
        for label, statement in (
            ("ALLOWED after FAILED", decision_row(SLOT_B, OTHER_RUN_ID, "ALLOWED")),
            (
                "ALLOWED after UNAVAILABLE",
                decision_row(
                    SLOT_B,
                    OTHER_RUN_ID,
                    "ALLOWED",
                    predecessor_terminal_state="UNAVAILABLE",
                    availability_observation_id=AVAIL_A,
                ),
            ),
            (
                "DENIED hard-blocked",
                decision_row(
                    SLOT_B,
                    OTHER_RUN_ID,
                    "DENIED",
                    denial_reason="HARD_BLOCKED_OUTCOME",
                    hard_block_error_code="ENGINE.RUNTIME_FAILURE",
                ),
            ),
            (
                "DENIED not fresh",
                decision_row(
                    SLOT_B,
                    OTHER_RUN_ID,
                    "DENIED",
                    predecessor_terminal_state="UNAVAILABLE",
                    denial_reason="AVAILABILITY_OBSERVATION_NOT_FRESH",
                ),
            ),
        )
    ),
    *(
        (f"a shape-valid {kind} owner", *statement)
        for kind, statement in (
            (
                "RUN without invocation",
                owner_row(
                    _new_hash(3),
                    "RUN",
                    experiment_id=EXPERIMENT_ID,
                    run_id=OTHER_RUN_ID,
                ),
            ),
            (
                "EXPERIMENT",
                owner_row(_new_hash(3), "EXPERIMENT", experiment_id=EXPERIMENT_ID),
            ),
            ("DATASET", owner_row(_new_hash(3), "DATASET", dataset_id=DS_A)),
            (
                "STRATEGY by id",
                owner_row(_new_hash(3), "STRATEGY", strategy_version_id=STRV_A),
            ),
            (
                "STRATEGY by hash",
                owner_row(
                    _new_hash(3), "STRATEGY", strategy_version_hash=STRATEGY_HASH
                ),
            ),
            (
                "ADAPTER",
                owner_row(
                    _new_hash(3),
                    "ADAPTER",
                    adapter_name="adapter.alpha",
                    adapter_version="1.0.0",
                ),
            ),
            (
                "ADAPTER with engine",
                owner_row(
                    _new_hash(3),
                    "ADAPTER",
                    adapter_name="adapter.alpha",
                    adapter_version="1.0.0",
                    engine_name="engine.alpha",
                    engine_version="2.3.4",
                ),
            ),
            (
                "SYSTEM",
                owner_row(
                    _new_hash(3),
                    "SYSTEM",
                    core_component="core.scheduler",
                    correlation_id="corr-1",
                ),
            ),
        )
    ),
)


@pytest.mark.parametrize(
    ("statement", "parameters", "expected_code"),
    [
        pytest.param(sql, params, expected, id=label)
        for label, sql, params, expected in TERMINAL_STATE_CHANGE_STATEMENTS
    ],
)
def test_every_trigger_and_state_check_fires(
    seeded_database: SqliteDatabase,
    statement: str,
    parameters: tuple[object, ...],
    expected_code: str,
) -> None:
    with seeded_database.connection() as connection:
        with pytest.raises(IntegrityError) as caught:
            connection.exec_driver_sql(statement, parameters)
        assert seeded_database.classify(caught.value) == expected_code
        connection.rollback()


@pytest.mark.parametrize(
    ("statement", "parameters"),
    [
        pytest.param(statement, parameters, id=label)
        for label, statement, parameters in PERMITTED_STATEMENTS
    ],
)
def test_the_permitted_writes_pass(
    seeded_database: SqliteDatabase, statement: str, parameters: tuple[object, ...]
) -> None:
    with seeded_database.connection() as connection:
        result = connection.exec_driver_sql(statement, parameters)
        assert result.rowcount == 1
        connection.commit()


def test_the_seed_holds_one_row_per_table(seeded_database: SqliteDatabase) -> None:
    """Every table of plan 6.4 holds at least one seeded row and the seed satisfies
    every constraint (the fixture would have raised otherwise)."""
    with seeded_database.read_only() as connection:
        for table in (
            "experiments",
            "engine_slots",
            "runtime_availability_observations",
            "diagnostics",
            "diagnostic_causes",
            "strategy_versions",
            "datasets",
            "dataset_partitions",
            "engine_runs",
            "command_invocations",
            "run_events",
            "retry_decisions",
            "artifact_owners",
        ):
            count = connection.exec_driver_sql(f"SELECT count(*) FROM {table}")  # noqa: S608
            assert count.scalar_one() >= 1, table
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
