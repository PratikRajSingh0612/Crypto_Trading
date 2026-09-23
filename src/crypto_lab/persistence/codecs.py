"""Lossless row codecs for every persisted record (plan 3.1-3.3, Task 3).

One encoder/decoder pair per record of plan section 3.1, following the single
encoding authority of section 3.2 and the column tables of section 3.3. Ingress
(``encode_<record>``) is the inverse projection of an already-validated record:
the record is dumped in JSON mode, every text, enum, hash and identifier column
copies its field verbatim (E1, E2), a boolean becomes ``0``/``1`` (E3), an
instant becomes exact integer microseconds since the epoch (E5,
``utc_to_micros``), a nested value object with a fixed field set is flattened
to typed columns (N5) and every other nested value -- a spec, a policy, a
payload, ``details``, a sorted identifier tuple, a whole registry record -- is a
canonical-JSON snapshot column (E7, E8). A ``MISSING`` field is ``NULL`` and an
empty tuple is the text ``[]`` (N1, N2). The codec never re-derives a hash: it
copies the record's, and the record validators recompute on the next egress.

Egress is one mechanism for every record (reading 10): assemble a JSON-mode
payload from the row -- text verbatim, ``col == 1`` for booleans, ``format_utc``
text for instants (``micros_to_utc_text``), the parsed snapshot for E7 columns
(``load_snapshot``, which refuses ``NaN``/``Infinity``), the nested identities
rebuilt from their flattened columns, and no key at all for a ``NULL`` N1
column, never a JSON ``null`` -- then ``Record.model_validate_json`` over
``canonical_json_bytes(payload)``, so strict JSON-mode validation re-checks
every invariant of the record. A ``ValidationError``, a column outside its
encoding (wrong SQL type, an instant outside the E5 range, a snapshot that is
not canonical JSON or holds ``null``, a partially ``NULL`` flattened identity) or
a payload canonical JSON refuses (a stored float) is ``CORE.INVARIANT_VIOLATION``
carrying ``table``, ``identity`` and the first error ``location`` in ``details``.
Every ``egress_payload_<record>(row)`` is exposed so a test can assert on the
payload before validation (rule N1).

Two declared readings beyond the tables: ``decode_observation`` also refuses a
row whose persistence-owned ``content_sha256`` differs from the fingerprint
recomputed over the decoded record, and ``decode_artifact_owner`` refuses a row
whose ``owner_hash`` differs from ``artifact_owner_hash`` of the rebuilt
variant -- both columns are identities of the row and derived from the record
alone, so a disagreement is an inconsistent stored representation. Rule N4:
``encode_engine_run`` raises ``ValueError`` when the record carries
``finalization_deadline_utc`` (no column exists; a validated record never does).
The typed projection columns of the registry tables (rule N6) are written from
the same record and never read to rebuild it; ``consistency_report()`` measures
their agreement.

Decoders take the injected ``Clock`` as a keyword: a ``Failure`` diagnostic is
stamped from it (plan 6.5) and this module reads no clock of its own. The module
imports no SQLAlchemy and names the tables as literals; a row is any
``Mapping[str, object]``, the shape a SQLAlchemy ``RowMapping`` presents.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from pydantic import BaseModel, ValidationError

from crypto_lab.adapters.events import RunEvent
from crypto_lab.artifacts.ownership import (
    ARTIFACT_OWNER_ADAPTER,
    ArtifactOwnerRef,
    artifact_owner_hash,
)
from crypto_lab.datasets.models import DatasetDescriptor, DatasetPartition
from crypto_lab.domain.canonical_json import canonical_json_bytes, canonical_json_text
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.descriptors import RuntimeAvailabilityObservation
from crypto_lab.domain.diagnostics import Diagnostic, DiagnosticDetailValue
from crypto_lab.domain.engine_run import EngineRunRecord
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.retry import RetryDecisionRecord
from crypto_lab.domain.time import format_utc, require_utc
from crypto_lab.persistence.diagnostics import (
    INVARIANT_VIOLATION,
    persistence_failure,
)
from crypto_lab.strategy.versioning import StrategyVersion

__all__ = [
    "EPOCH",
    "ColumnError",
    "RowValues",
    "decode_artifact_owner",
    "decode_command_invocation",
    "decode_dataset",
    "decode_dataset_partition",
    "decode_diagnostic",
    "decode_engine_run",
    "decode_experiment",
    "decode_observation",
    "decode_retry_decision",
    "decode_run_event",
    "decode_strategy_version",
    "egress_payload_artifact_owner",
    "egress_payload_command_invocation",
    "egress_payload_dataset",
    "egress_payload_dataset_partition",
    "egress_payload_diagnostic",
    "egress_payload_engine_run",
    "egress_payload_experiment",
    "egress_payload_observation",
    "egress_payload_retry_decision",
    "egress_payload_run_event",
    "egress_payload_strategy_version",
    "encode_artifact_owner",
    "encode_command_invocation",
    "encode_dataset",
    "encode_dataset_partition",
    "encode_diagnostic",
    "encode_engine_run",
    "encode_engine_slots",
    "encode_experiment",
    "encode_observation",
    "encode_retry_decision",
    "encode_run_event",
    "encode_strategy_version",
    "load_snapshot",
    "micros_to_utc_text",
    "utc_to_micros",
]

#: One row's column values as the codec writes them: text, integer or ``NULL``.
type RowValues = dict[str, str | int | None]
#: A JSON-mode egress payload before validation.
type Payload = dict[str, object]

#: Encoding E5: instants are microseconds since this epoch, exact integers.
EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND: Final = timedelta(microseconds=1)
#: ``0001-01-01T00:00:00Z`` through ``9999-12-31T23:59:59.999999Z`` (schema CHECK).
_MIN_INSTANT_MICROS: Final = -62_135_596_800_000_000
_MAX_INSTANT_MICROS: Final = 253_402_300_799_999_999

#: The twelve nullable variant columns of ``artifact_owners`` (plan 3.3.12).
_OWNER_COLUMNS: Final[tuple[str, ...]] = (
    "experiment_id",
    "run_id",
    "invocation_id",
    "dataset_id",
    "strategy_version_id",
    "strategy_version_hash",
    "adapter_name",
    "adapter_version",
    "engine_name",
    "engine_version",
    "core_component",
    "correlation_id",
)
#: The five flattened ``ProcessIdentity`` columns (N5), all ``NULL`` or all present.
_PROCESS_IDENTITY_COLUMNS: Final[tuple[str, ...]] = (
    "pid",
    "creation_identity",
    "executable_path",
    "executable_hash",
    "supervisor_instance_id",
)


# --------------------------------------------------------------------------
# Scalar encodings (E3, E5, E7)
# --------------------------------------------------------------------------


def utc_to_micros(value: datetime) -> int:
    """E5 ingress: exact integer microseconds since the epoch of a UTC instant.

    Integer arithmetic on the UTC-normalized ``datetime`` (never ``timestamp()``
    floats); negative before 1970.
    """
    return (require_utc(value) - EPOCH) // _MICROSECOND


def micros_to_utc_text(value: int) -> str:
    """E5 egress: the canonical ``format_utc`` text of a column integer.

    A value outside the E5 range is ``ValueError``; a non-integer is ``TypeError``.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("an instant column holds a built-in integer")
    if not _MIN_INSTANT_MICROS <= value <= _MAX_INSTANT_MICROS:
        raise ValueError("instant column is outside the E5 range")
    return format_utc(EPOCH + timedelta(microseconds=value))


def _refuse_constant(name: str) -> object:
    raise ValueError(f"stored snapshot contains the non-finite constant {name}")


def load_snapshot(text: str) -> object:
    """E7 egress: parse a canonical-JSON column; ``NaN``/``Infinity`` are refused."""
    return json.loads(text, parse_constant=_refuse_constant)


def _snapshot(value: object) -> str:
    """E7 ingress: the canonical compact JSON text of a dumped value."""
    return canonical_json_text(value)


def _optional_snapshot(value: object | None) -> str | None:
    return None if value is None else _snapshot(value)


def _flag(value: object) -> int:
    if type(value) is not bool:
        raise TypeError("a boolean column is written from a built-in bool")
    return 1 if value else 0


def _instant_or_null(value: object) -> int | None:
    """N1 + E5: a ``MISSING`` instant is ``NULL``; a present one is its integer."""
    if isinstance(value, datetime):
        return utc_to_micros(value)
    if isinstance(value, bool | int | str | float | bytes | list | tuple | dict):
        raise TypeError("an instant field holds a datetime or MISSING")
    return None


def _dump(record: BaseModel) -> dict[str, Any]:
    """The record in JSON mode: ``MISSING`` keys omitted, instants and decimals text."""
    return record.model_dump(mode="json")


# --------------------------------------------------------------------------
# Column readers for egress (E1-E8, N1-N5)
# --------------------------------------------------------------------------


class ColumnError(ValueError):
    """A stored column outside its encoding; names the column (reading 10)."""

    def __init__(self, column: str, reason: str) -> None:
        super().__init__(f"column {column} {reason}")
        self.column = column


class _Columns:
    """Typed readers over one row mapping; every mismatch is a ``ColumnError``."""

    __slots__ = ("_row",)

    def __init__(self, row: Mapping[str, object]) -> None:
        self._row = row

    def _raw(self, column: str) -> object:
        if column not in self._row:
            raise ColumnError(column, "is absent from the row")
        return self._row[column]

    def text(self, column: str) -> str:
        value = self._raw(column)
        if type(value) is not str:
            raise ColumnError(column, "is not text")
        return value

    def optional_text(self, column: str) -> str | None:
        if self._raw(column) is None:
            return None
        return self.text(column)

    def integer(self, column: str) -> int:
        value = self._raw(column)
        if type(value) is not int:
            raise ColumnError(column, "is not an integer")
        return value

    def optional_integer(self, column: str) -> int | None:
        if self._raw(column) is None:
            return None
        return self.integer(column)

    def boolean(self, column: str) -> bool:
        value = self.integer(column)
        if value not in (0, 1):
            raise ColumnError(column, "is not 0 or 1")
        return value == 1

    def instant(self, column: str) -> str:
        try:
            return micros_to_utc_text(self.integer(column))
        except (ValueError, OverflowError) as error:
            raise ColumnError(column, "is outside the E5 range") from error

    def optional_instant(self, column: str) -> str | None:
        if self._raw(column) is None:
            return None
        return self.instant(column)

    def json(self, column: str) -> object:
        text = self.text(column)
        try:
            document = load_snapshot(text)
        except ValueError as error:
            raise ColumnError(column, "is not canonical JSON") from error
        if document is None:
            raise ColumnError(column, "holds JSON null")
        return document

    def optional_json(self, column: str) -> object | None:
        if self._raw(column) is None:
            return None
        return self.json(column)

    def json_object(self, column: str) -> dict[str, object]:
        document = self.json(column)
        if not isinstance(document, dict):
            raise ColumnError(column, "is not a JSON object")
        return document


def _put(payload: Payload, key: str, value: object | None) -> None:
    """Rule N1: a ``NULL`` column contributes no key; a value is embedded as is."""
    if value is not None:
        payload[key] = value


def _location(error: ValidationError) -> str:
    """The first error's location; a model-level rule has none and reads ``record``."""
    return ".".join(str(part) for part in error.errors()[0]["loc"]) or "record"


def _egress[T](
    *,
    table: str,
    identity_column: str,
    row: Mapping[str, object],
    build: Callable[[Mapping[str, object]], Payload],
    validate: Callable[[bytes], T],
    clock: Clock,
) -> T | Failure:
    """Reading 10: the payload, then JSON-mode validation; a refusal is INV."""
    identity = str(row.get(identity_column))
    try:
        payload = build(row)
        return validate(canonical_json_bytes(payload))
    except ValidationError as error:
        location = _location(error)
    except ColumnError as error:
        location = error.column
    except (TypeError, ValueError):
        location = "payload"
    return _invariant(table, identity, location, clock)


def _invariant(table: str, identity: str, location: str, clock: Clock) -> Failure:
    details: dict[str, DiagnosticDetailValue] = {
        "table": table,
        "identity": identity,
        "location": location,
        "operation": "decode",
    }
    return persistence_failure(
        INVARIANT_VIOLATION,
        message=f"stored {table} row failed egress validation",
        clock=clock,
        details=details,
    )


# --------------------------------------------------------------------------
# 3.3.1 experiments and 3.3.2 engine_slots
# --------------------------------------------------------------------------


def encode_experiment(record: ExperimentRecord) -> RowValues:
    """The ``experiments`` row of a record; the snapshot columns are not written."""
    dumped = _dump(record)
    return {
        "experiment_id": dumped["experiment_id"],
        "schema_version": dumped["schema_version"],
        "state": dumped["state"],
        "spec": _snapshot(dumped["spec"]),
        "spec_hash": dumped["spec_hash"],
        "strategy_version_hash": dumped["spec"]["strategy_version_hash"],
        "dataset_version_hash": dumped["spec"]["dataset_version_hash"],
        "slot_compatibility": _optional_snapshot(dumped.get("slot_compatibility")),
        "cancellation_correlation_id": dumped.get("cancellation_correlation_id"),
        "created_at_utc": utc_to_micros(record.created_at_utc),
        "updated_at_utc": utc_to_micros(record.updated_at_utc),
        "revision": dumped["revision"],
    }


def encode_engine_slots(record: ExperimentRecord) -> tuple[RowValues, ...]:
    """The ``engine_slots`` projection of ``spec.selected_engine_slots`` (3.3.2)."""
    dumped = _dump(record)
    return tuple(
        {
            "experiment_id": dumped["experiment_id"],
            "logical_slot_id": slot["logical_slot_id"],
            "slot_ordinal": slot["slot_ordinal"],
            "adapter_name": slot["adapter"]["adapter_name"],
            "adapter_version": slot["adapter"]["adapter_version"],
            "engine_name": slot["engine"]["engine_name"],
            "engine_version": slot["engine"]["engine_version"],
        }
        for slot in dumped["spec"]["selected_engine_slots"]
    )


def egress_payload_experiment(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "experiment_id": columns.text("experiment_id"),
        "spec": columns.json("spec"),
        "spec_hash": columns.text("spec_hash"),
        "state": columns.text("state"),
        "created_at_utc": columns.instant("created_at_utc"),
        "updated_at_utc": columns.instant("updated_at_utc"),
        "revision": columns.integer("revision"),
    }
    _put(payload, "slot_compatibility", columns.optional_json("slot_compatibility"))
    _put(
        payload,
        "cancellation_correlation_id",
        columns.optional_text("cancellation_correlation_id"),
    )
    return payload


def decode_experiment(
    row: Mapping[str, object], *, clock: Clock
) -> Result[ExperimentRecord]:
    outcome = _egress(
        table="experiments",
        identity_column="experiment_id",
        row=row,
        build=egress_payload_experiment,
        validate=ExperimentRecord.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[ExperimentRecord](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.3 engine_runs
# --------------------------------------------------------------------------


def encode_engine_run(record: EngineRunRecord) -> RowValues:
    """The ``engine_runs`` row; rule N4 refuses a present finalization deadline."""
    dumped = _dump(record)
    if "finalization_deadline_utc" in dumped:
        raise ValueError(
            "finalization_deadline_utc has no column (rule N4): the record must "
            "carry it MISSING"
        )
    return {
        "run_id": dumped["run_id"],
        "schema_version": dumped["schema_version"],
        "experiment_id": dumped["experiment_id"],
        "logical_slot_id": dumped["logical_slot_id"],
        "attempt_number": dumped["attempt_number"],
        "attempt_token_hash": dumped["attempt_token_hash"],
        "state": dumped["state"],
        "adapter_name": dumped["adapter"]["adapter_name"],
        "adapter_version": dumped["adapter"]["adapter_version"],
        "engine_name": dumped["engine"]["engine_name"],
        "engine_version": dumped["engine"]["engine_version"],
        "request_hash": dumped["request_hash"],
        "predecessor_run_id": dumped.get("predecessor_run_id"),
        "retry_reason": dumped.get("retry_reason"),
        "primary_terminal_diagnostic_id": dumped.get("primary_terminal_diagnostic_id"),
        "availability_observation_id": dumped.get("availability_observation_id"),
        "created_at_utc": utc_to_micros(record.created_at_utc),
        "updated_at_utc": utc_to_micros(record.updated_at_utc),
        "revision": dumped["revision"],
    }


def egress_payload_engine_run(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "run_id": columns.text("run_id"),
        "experiment_id": columns.text("experiment_id"),
        "logical_slot_id": columns.text("logical_slot_id"),
        "attempt_number": columns.integer("attempt_number"),
        "attempt_token_hash": columns.text("attempt_token_hash"),
        "state": columns.text("state"),
        "adapter": {
            "adapter_name": columns.text("adapter_name"),
            "adapter_version": columns.text("adapter_version"),
        },
        "engine": {
            "engine_name": columns.text("engine_name"),
            "engine_version": columns.text("engine_version"),
        },
        "request_hash": columns.text("request_hash"),
        "created_at_utc": columns.instant("created_at_utc"),
        "updated_at_utc": columns.instant("updated_at_utc"),
        "revision": columns.integer("revision"),
    }
    for column in (
        "predecessor_run_id",
        "retry_reason",
        "primary_terminal_diagnostic_id",
        "availability_observation_id",
    ):
        _put(payload, column, columns.optional_text(column))
    return payload


def decode_engine_run(
    row: Mapping[str, object], *, clock: Clock
) -> Result[EngineRunRecord]:
    outcome = _egress(
        table="engine_runs",
        identity_column="run_id",
        row=row,
        build=egress_payload_engine_run,
        validate=EngineRunRecord.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[EngineRunRecord](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.4 command_invocations
# --------------------------------------------------------------------------


def encode_command_invocation(record: CommandInvocationRecord) -> RowValues:
    """The ``command_invocations`` row; ``pid_identity`` is flattened (N5)."""
    dumped = _dump(record)
    identity = dumped.get("pid_identity")
    values: RowValues = {
        "invocation_id": dumped["invocation_id"],
        "schema_version": dumped["schema_version"],
        "command_kind": dumped["command_kind"],
        "adapter_name": dumped["adapter_name"],
        "adapter_version": dumped["adapter_version"],
        "run_id": dumped.get("run_id"),
        "request_hash": dumped["request_hash"],
        "timeout_seconds": dumped["timeout_seconds"],
        "state": dumped["state"],
        "process_created": _flag(dumped["process_created"]),
        "launch_attempted_at_utc": _instant_or_null(record.launch_attempted_at_utc),
        "deadline_utc": _instant_or_null(record.deadline_utc),
        "process_started_at_utc": _instant_or_null(record.process_started_at_utc),
        "completed_at_utc": _instant_or_null(record.completed_at_utc),
        "native_exit_value": dumped.get("native_exit_value"),
        "process_exit_category": dumped.get("process_exit_category"),
        "cleanup_complete": _flag(dumped["cleanup_complete"]),
        "cleanup_completed_at_utc": _instant_or_null(record.cleanup_completed_at_utc),
        "stderr_artifact_id": dumped.get("stderr_artifact_id"),
        "primary_diagnostic_id": dumped.get("primary_diagnostic_id"),
        "diagnostic_ids": _snapshot(dumped["diagnostic_ids"]),
        "created_at_utc": utc_to_micros(record.created_at_utc),
        "updated_at_utc": utc_to_micros(record.updated_at_utc),
        "revision": dumped["revision"],
    }
    for column in _PROCESS_IDENTITY_COLUMNS:
        values[column] = None if identity is None else identity[column]
    return values


def _process_identity(columns: _Columns) -> dict[str, object] | None:
    """N5: the five flattened columns are all ``NULL`` or all present."""
    present = tuple(
        columns.optional_integer(column) is not None
        if column == "pid"
        else columns.optional_text(column) is not None
        for column in _PROCESS_IDENTITY_COLUMNS
    )
    if not any(present):
        return None
    if not all(present):
        raise ColumnError("pid", "process identity columns are partially null")
    return {
        "pid": columns.integer("pid"),
        "creation_identity": columns.text("creation_identity"),
        "executable_path": columns.text("executable_path"),
        "executable_hash": columns.text("executable_hash"),
        "supervisor_instance_id": columns.text("supervisor_instance_id"),
    }


def egress_payload_command_invocation(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "invocation_id": columns.text("invocation_id"),
        "command_kind": columns.text("command_kind"),
        "adapter_name": columns.text("adapter_name"),
        "adapter_version": columns.text("adapter_version"),
        "request_hash": columns.text("request_hash"),
        "timeout_seconds": columns.integer("timeout_seconds"),
        "state": columns.text("state"),
        "process_created": columns.boolean("process_created"),
        "cleanup_complete": columns.boolean("cleanup_complete"),
        "diagnostic_ids": columns.json("diagnostic_ids"),
        "created_at_utc": columns.instant("created_at_utc"),
        "updated_at_utc": columns.instant("updated_at_utc"),
        "revision": columns.integer("revision"),
    }
    _put(payload, "run_id", columns.optional_text("run_id"))
    _put(payload, "deadline_utc", columns.optional_instant("deadline_utc"))
    _put(
        payload,
        "launch_attempted_at_utc",
        columns.optional_instant("launch_attempted_at_utc"),
    )
    _put(
        payload,
        "process_started_at_utc",
        columns.optional_instant("process_started_at_utc"),
    )
    _put(payload, "pid_identity", _process_identity(columns))
    _put(payload, "completed_at_utc", columns.optional_instant("completed_at_utc"))
    _put(payload, "native_exit_value", columns.optional_integer("native_exit_value"))
    _put(
        payload, "process_exit_category", columns.optional_text("process_exit_category")
    )
    _put(
        payload,
        "cleanup_completed_at_utc",
        columns.optional_instant("cleanup_completed_at_utc"),
    )
    _put(payload, "stderr_artifact_id", columns.optional_text("stderr_artifact_id"))
    _put(
        payload, "primary_diagnostic_id", columns.optional_text("primary_diagnostic_id")
    )
    return payload


def decode_command_invocation(
    row: Mapping[str, object], *, clock: Clock
) -> Result[CommandInvocationRecord]:
    outcome = _egress(
        table="command_invocations",
        identity_column="invocation_id",
        row=row,
        build=egress_payload_command_invocation,
        validate=CommandInvocationRecord.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[CommandInvocationRecord](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.5 run_events
# --------------------------------------------------------------------------


def encode_run_event(record: RunEvent) -> RowValues:
    """The ``run_events`` row; the payload is the union rendered by the record."""
    dumped = _dump(record)
    return {
        "invocation_id": dumped["invocation_id"],
        "sequence": dumped["sequence"],
        "event_id": dumped["event_id"],
        "run_id": dumped["run_id"],
        "schema_version": dumped["schema_version"],
        "protocol_version": dumped["protocol_version"],
        "attempt_token_hash": dumped["attempt_token_hash"],
        "wire_event_hash": dumped["wire_event_hash"],
        "content_hash": dumped["content_hash"],
        "event_type": dumped["event_type"],
        "timestamp_utc": utc_to_micros(record.timestamp_utc),
        "received_at_utc": utc_to_micros(record.received_at_utc),
        "payload": _snapshot(dumped["payload"]),
    }


def egress_payload_run_event(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    return {
        "schema_version": columns.text("schema_version"),
        "protocol_version": columns.text("protocol_version"),
        "event_id": columns.text("event_id"),
        "invocation_id": columns.text("invocation_id"),
        "run_id": columns.text("run_id"),
        "attempt_token_hash": columns.text("attempt_token_hash"),
        "sequence": columns.integer("sequence"),
        "event_type": columns.text("event_type"),
        "timestamp_utc": columns.instant("timestamp_utc"),
        "payload": columns.json_object("payload"),
        "received_at_utc": columns.instant("received_at_utc"),
        "wire_event_hash": columns.text("wire_event_hash"),
        "content_hash": columns.text("content_hash"),
    }


def decode_run_event(row: Mapping[str, object], *, clock: Clock) -> Result[RunEvent]:
    outcome = _egress(
        table="run_events",
        identity_column="event_id",
        row=row,
        build=egress_payload_run_event,
        validate=RunEvent.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[RunEvent](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.6 retry_decisions
# --------------------------------------------------------------------------


def encode_retry_decision(record: RetryDecisionRecord) -> RowValues:
    dumped = _dump(record)
    return {
        "logical_slot_id": dumped["logical_slot_id"],
        "predecessor_run_id": dumped["predecessor_run_id"],
        "schema_version": dumped["schema_version"],
        "experiment_id": dumped["experiment_id"],
        "experiment_spec_hash": dumped["experiment_spec_hash"],
        "retry_policy": _snapshot(dumped["retry_policy"]),
        "created_attempt_count": dumped["created_attempt_count"],
        "predecessor_terminal_state": dumped["predecessor_terminal_state"],
        "primary_terminal_diagnostic_id": dumped["primary_terminal_diagnostic_id"],
        "outcome": dumped["outcome"],
        "denial_reason": dumped.get("denial_reason"),
        "hard_block_error_code": dumped.get("hard_block_error_code"),
        "availability_observation_id": dumped.get("availability_observation_id"),
        "retry_not_before_utc": _instant_or_null(record.retry_not_before_utc),
        "reserved_successor_attempt_number": dumped.get(
            "reserved_successor_attempt_number"
        ),
        "decided_at_utc": utc_to_micros(record.decided_at_utc),
    }


def egress_payload_retry_decision(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "experiment_id": columns.text("experiment_id"),
        "logical_slot_id": columns.text("logical_slot_id"),
        "predecessor_run_id": columns.text("predecessor_run_id"),
        "experiment_spec_hash": columns.text("experiment_spec_hash"),
        "retry_policy": columns.json_object("retry_policy"),
        "created_attempt_count": columns.integer("created_attempt_count"),
        "predecessor_terminal_state": columns.text("predecessor_terminal_state"),
        "primary_terminal_diagnostic_id": columns.text(
            "primary_terminal_diagnostic_id"
        ),
        "outcome": columns.text("outcome"),
        "decided_at_utc": columns.instant("decided_at_utc"),
    }
    _put(payload, "denial_reason", columns.optional_text("denial_reason"))
    _put(
        payload, "hard_block_error_code", columns.optional_text("hard_block_error_code")
    )
    _put(
        payload,
        "availability_observation_id",
        columns.optional_text("availability_observation_id"),
    )
    _put(
        payload,
        "retry_not_before_utc",
        columns.optional_instant("retry_not_before_utc"),
    )
    _put(
        payload,
        "reserved_successor_attempt_number",
        columns.optional_integer("reserved_successor_attempt_number"),
    )
    return payload


def decode_retry_decision(
    row: Mapping[str, object], *, clock: Clock
) -> Result[RetryDecisionRecord]:
    outcome = _egress(
        table="retry_decisions",
        identity_column="predecessor_run_id",
        row=row,
        build=egress_payload_retry_decision,
        validate=RetryDecisionRecord.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[RetryDecisionRecord](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.7 runtime_availability_observations
# --------------------------------------------------------------------------


def _observation_fingerprint(dumped: Mapping[str, object]) -> str:
    """Plan 3.3.7: the persistence-owned integrity fingerprint of one observation."""
    return sha256_bytes(canonical_json_bytes(dumped))


def encode_observation(record: RuntimeAvailabilityObservation) -> RowValues:
    dumped = _dump(record)
    return {
        "availability_observation_id": dumped["availability_observation_id"],
        "schema_version": dumped["schema_version"],
        "adapter_name": dumped["adapter_name"],
        "adapter_version": dumped["adapter_version"],
        "executable_path": dumped["executable_path"],
        "executable_hash": dumped["executable_hash"],
        "runtime_version": dumped["runtime_version"],
        "operating_system": dumped["operating_system"],
        "available": _flag(dumped["available"]),
        "reason_code": dumped.get("reason_code"),
        "observed_at_utc": utc_to_micros(record.observed_at_utc),
        "expires_at_utc": utc_to_micros(record.expires_at_utc),
        "network_required": _flag(dumped["network_required"]),
        "credentials_required": _flag(dumped["credentials_required"]),
        "content_sha256": _observation_fingerprint(dumped),
    }


def egress_payload_observation(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "availability_observation_id": columns.text("availability_observation_id"),
        "adapter_name": columns.text("adapter_name"),
        "adapter_version": columns.text("adapter_version"),
        "executable_path": columns.text("executable_path"),
        "executable_hash": columns.text("executable_hash"),
        "runtime_version": columns.text("runtime_version"),
        "operating_system": columns.text("operating_system"),
        "available": columns.boolean("available"),
        "observed_at_utc": columns.instant("observed_at_utc"),
        "expires_at_utc": columns.instant("expires_at_utc"),
        "network_required": columns.boolean("network_required"),
        "credentials_required": columns.boolean("credentials_required"),
    }
    _put(payload, "reason_code", columns.optional_text("reason_code"))
    return payload


def decode_observation(
    row: Mapping[str, object], *, clock: Clock
) -> Result[RuntimeAvailabilityObservation]:
    table = "runtime_availability_observations"
    outcome = _egress(
        table=table,
        identity_column="availability_observation_id",
        row=row,
        build=egress_payload_observation,
        validate=RuntimeAvailabilityObservation.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    stored = row.get("content_sha256")
    if stored != _observation_fingerprint(_dump(outcome)):
        identity = str(row.get("availability_observation_id"))
        return _invariant(table, identity, "content_sha256", clock)
    return Success[RuntimeAvailabilityObservation](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.8 diagnostics
# --------------------------------------------------------------------------


def encode_diagnostic(record: Diagnostic) -> RowValues:
    """The ``diagnostics`` row; the causal tuple is serialized through the dump."""
    dumped = _dump(record)
    return {
        "diagnostic_id": dumped["diagnostic_id"],
        "schema_version": dumped["schema_version"],
        "severity": dumped["severity"],
        "error_code": dumped["error_code"],
        "category": dumped["category"],
        "message": dumped["message"],
        "source_component": dumped["source_component"],
        "experiment_id": dumped.get("experiment_id"),
        "run_id": dumped.get("run_id"),
        "invocation_id": dumped.get("invocation_id"),
        "engine": dumped.get("engine"),
        "retriable": _flag(dumped["retriable"]),
        "timestamp_utc": utc_to_micros(record.timestamp_utc),
        "details": _snapshot(dumped["details"]),
        "causal_diagnostic_ids": _snapshot(dumped["causal_diagnostic_ids"]),
    }


def egress_payload_diagnostic(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "diagnostic_id": columns.text("diagnostic_id"),
        "severity": columns.text("severity"),
        "error_code": columns.text("error_code"),
        "category": columns.text("category"),
        "message": columns.text("message"),
        "source_component": columns.text("source_component"),
        "retriable": columns.boolean("retriable"),
        "timestamp_utc": columns.instant("timestamp_utc"),
        "details": columns.json_object("details"),
        "causal_diagnostic_ids": columns.json("causal_diagnostic_ids"),
    }
    for column in ("experiment_id", "run_id", "invocation_id", "engine"):
        _put(payload, column, columns.optional_text(column))
    return payload


def decode_diagnostic(row: Mapping[str, object], *, clock: Clock) -> Result[Diagnostic]:
    outcome = _egress(
        table="diagnostics",
        identity_column="diagnostic_id",
        row=row,
        build=egress_payload_diagnostic,
        validate=Diagnostic.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[Diagnostic](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.10 strategy_versions
# --------------------------------------------------------------------------


def encode_strategy_version(record: StrategyVersion) -> RowValues:
    """The whole record as the E7 ``record`` column plus its index projections (N6)."""
    dumped = _dump(record)
    return {
        "content_hash": dumped["content_hash"],
        "strategy_version_id": dumped["strategy_version_id"],
        "strategy_id": dumped["strategy_id"],
        "schema_version": dumped["schema_version"],
        "record": _snapshot(dumped),
        "hashing_profile_version": dumped["hashing_profile_version"],
        "created_at_utc": utc_to_micros(record.created_at_utc),
    }


def egress_payload_strategy_version(row: Mapping[str, object]) -> Payload:
    return _Columns(row).json_object("record")


def decode_strategy_version(
    row: Mapping[str, object], *, clock: Clock
) -> Result[StrategyVersion]:
    outcome = _egress(
        table="strategy_versions",
        identity_column="content_hash",
        row=row,
        build=egress_payload_strategy_version,
        validate=StrategyVersion.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[StrategyVersion](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.11 datasets and dataset_partitions
# --------------------------------------------------------------------------


def encode_dataset(record: DatasetDescriptor) -> RowValues:
    """The whole descriptor as the E7 ``record`` column plus the index projections."""
    dumped = _dump(record)
    return {
        "dataset_id": dumped["dataset_id"],
        "content_hash": dumped["content_hash"],
        "schema_version": dumped["schema_version"],
        "record": _snapshot(dumped),
        "venue": dumped["venue"],
        "instrument_canonical_id": dumped["instrument"]["canonical_id"],
        "data_type": dumped["data_type"],
        "timeframe": dumped.get("timeframe"),
        "start_utc": utc_to_micros(record.start_utc),
        "end_utc": utc_to_micros(record.end_utc),
        "validation_status": dumped["validation_status"],
        "created_at_utc": utc_to_micros(record.created_at_utc),
    }


def egress_payload_dataset(row: Mapping[str, object]) -> Payload:
    return _Columns(row).json_object("record")


def decode_dataset(
    row: Mapping[str, object], *, clock: Clock
) -> Result[DatasetDescriptor]:
    outcome = _egress(
        table="datasets",
        identity_column="dataset_id",
        row=row,
        build=egress_payload_dataset,
        validate=DatasetDescriptor.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[DatasetDescriptor](outcome="SUCCESS", value=outcome)


def encode_dataset_partition(record: DatasetPartition) -> RowValues:
    dumped = _dump(record)
    return {
        "partition_id": dumped["partition_id"],
        "dataset_id": dumped["dataset_id"],
        "ordinal": dumped["ordinal"],
        "record": _snapshot(dumped),
        "content_hash": dumped["content_hash"],
        "raw_checksum": dumped["raw_checksum"],
        "normalized_checksum": dumped["normalized_checksum"],
        "relative_path": dumped["relative_path"],
        "row_count": dumped["row_count"],
        "start_utc": utc_to_micros(record.start_utc),
        "end_utc": utc_to_micros(record.end_utc),
    }


def egress_payload_dataset_partition(row: Mapping[str, object]) -> Payload:
    return _Columns(row).json_object("record")


def decode_dataset_partition(
    row: Mapping[str, object], *, clock: Clock
) -> Result[DatasetPartition]:
    outcome = _egress(
        table="dataset_partitions",
        identity_column="partition_id",
        row=row,
        build=egress_payload_dataset_partition,
        validate=DatasetPartition.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[DatasetPartition](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# 3.3.12 artifact_owners
# --------------------------------------------------------------------------


def encode_artifact_owner(owner: ArtifactOwnerRef) -> RowValues:
    """The ``artifact_owners`` row keyed by ``artifact_owner_hash`` (reading 8)."""
    dumped = _dump(owner)
    values: RowValues = {
        "owner_hash": artifact_owner_hash(owner),
        "owner_kind": dumped["owner_kind"],
    }
    for column in _OWNER_COLUMNS:
        values[column] = dumped.get(column)
    return values


def egress_payload_artifact_owner(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    payload: Payload = {"owner_kind": columns.text("owner_kind")}
    for column in _OWNER_COLUMNS:
        _put(payload, column, columns.optional_text(column))
    return payload


def decode_artifact_owner(
    row: Mapping[str, object], *, clock: Clock
) -> Result[ArtifactOwnerRef]:
    outcome = _egress(
        table="artifact_owners",
        identity_column="owner_hash",
        row=row,
        build=egress_payload_artifact_owner,
        validate=ARTIFACT_OWNER_ADAPTER.validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    if row.get("owner_hash") != artifact_owner_hash(outcome):
        return _invariant(
            "artifact_owners", str(row.get("owner_hash")), "owner_hash", clock
        )
    return Success[ArtifactOwnerRef](outcome="SUCCESS", value=outcome)
